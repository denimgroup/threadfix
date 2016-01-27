////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.email.EmailConfiguration;
import com.denimgroup.threadfix.service.email.EmailFilterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import javax.annotation.Nullable;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.*;

@Service
public class EmailReportServiceImpl implements EmailReportService {

    private static final SanitizedLogger LOG = new SanitizedLogger(EmailReportServiceImpl.class);

	@Autowired
	private VulnerabilitySearchService vulnerabilitySearchService;
	@Autowired
	private GenericSeverityService genericSeverityService;
	@Autowired
	private GenericVulnerabilityService genericVulnerabilityService;
	@Autowired
	private JavaMailSender javaMailSender;
	@Autowired
	private TemplateBuilderService templateBuilderService;
	@Autowired
	private EmailConfiguration emailConfiguration;
	@Autowired
	private EmailFilterService emailFilterService;
	@Autowired
	private DefaultConfigService defaultConfigService;
    @Nullable
    @Autowired(required = false)
	PolicyStatusService policyStatusService;

    private Set<String> getFilteredEmailAddresses(ScheduledEmailReport scheduledEmailReport) {

        List<String> emailAddresses = scheduledEmailReport.getEmailAddresses();
        List<EmailList> emailLists = scheduledEmailReport.getEmailLists();

        for (EmailList emailList : emailLists) {
            emailAddresses.addAll(emailList.getEmailAddresses());
        }

        return emailFilterService.getFilteredEmailAddresses(emailAddresses);
    }

	@Override
	public void sendEmailReport(ScheduledEmailReport scheduledEmailReport) {
		Set<String> filteredEmailAddresses = getFilteredEmailAddresses(scheduledEmailReport);
        List<Vulnerability> vulnerabilities = getNewVulnerabilities(scheduledEmailReport); //10 most severe vulns

        if (!emailConfiguration.isConfiguredEmail()){
			LOG.info("Email is not configured, not sending any email");
			return;
		}
		if (vulnerabilities.isEmpty()){
			LOG.info("No new vulnerability, not sending any email");
			return;
		}
		if (filteredEmailAddresses.isEmpty()){
			LOG.info("No valid email addresses, not sending any email");
			return;
		}

		//everything is ok, send the email
		String emailBody = getEmailReportBody(scheduledEmailReport);
		MimeMessage message = javaMailSender.createMimeMessage();
		try {
			message.setSubject(getEmailReportSubject(vulnerabilities));
			message.setContent(emailBody, "text/html; charset=utf-8");
			LOG.info("Filtered email addresses: " + filteredEmailAddresses.toString());
			for (String emailAddress : filteredEmailAddresses){
				message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(emailAddress));
			}
		} catch (MessagingException e) {
			e.printStackTrace();
		}
		try {
			javaMailSender.send(message);
			LOG.info("Email report sent normally sent normally");
		}
		catch (MailException ex) {
			LOG.error("Email not send because of misconfiguration", ex);
		}
	}

	//gets only 10 vulns with this parameters
	@Override
	public List<Vulnerability> getNewVulnerabilities(ScheduledEmailReport scheduledEmailReport) {
		VulnerabilitySearchParameters parameters = new VulnerabilitySearchParameters();
		configureDate(parameters, scheduledEmailReport);
		parameters.setGenericSeverities(getGenericSeveritiesAboveThreshold(scheduledEmailReport));
		parameters.setTeams(scheduledEmailReport.getOrganizations());
		parameters.setDescList(list("severity.intValue"));
		return vulnerabilitySearchService.performLookup(parameters);
	}

	private void configureDate(VulnerabilitySearchParameters parameters, ScheduledEmailReport scheduledEmailReport){
		Calendar targetDate = Calendar.getInstance();
		if (scheduledEmailReport.getFrequency().equals("Daily")){
			targetDate.add(Calendar.DAY_OF_YEAR, -1);
		} else {
			targetDate.add(Calendar.DAY_OF_YEAR, -7);
		}

		if (scheduledEmailReport.getPeriod().equals("PM")){
			targetDate.set(Calendar.AM_PM, Calendar.PM);
		} else {
			targetDate.set(Calendar.AM_PM, Calendar.AM);
		}
		targetDate.set(Calendar.HOUR, scheduledEmailReport.getHour());
		targetDate.set(Calendar.MINUTE, scheduledEmailReport.getMinute());
		targetDate.set(Calendar.SECOND, 0);
		targetDate.set(Calendar.MILLISECOND, 0);

		parameters.setStartDate(targetDate.getTime());
	}

	@Override
	public String getEmailReportBody(ScheduledEmailReport scheduledEmailReport) {
		Map<String, Object> model = getNewVulnerabilitiesHierarchicalModel(scheduledEmailReport);//will cut the vulns lists if more than 10 per generic vuln
		Object blockedEmailAddresses = emailFilterService.getBlockedEmailAddresses(scheduledEmailReport.getEmailAddresses());
		model.put("blockedEmailAddresses", blockedEmailAddresses);
		model.put("frequency", scheduledEmailReport.getFrequency());
		model.put("baseUrl", defaultConfigService.loadCurrentConfiguration().getBaseUrl());
		return templateBuilderService.prepareMessageFromTemplate(model, "scheduledEmailReport.vm");
	}

	@Override
	public String getEmailReportSubject(List<Vulnerability> vulnerabilities) {
		String maxSeverity = vulnerabilities.get(0).getGenericSeverity().getName();
		return "New vulnerabilitie(s) up to severity: " + maxSeverity;
	}

	@Override
	public Map<String, Object> getNewVulnerabilitiesHierarchicalModel(ScheduledEmailReport scheduledEmailReport) {
		VulnerabilitySearchParameters parameters = new VulnerabilitySearchParameters();
		configureDate(parameters, scheduledEmailReport);
		parameters.setUsingComponentsWithKnownVulnerabilities(false);
		List<Organization> organizations = scheduledEmailReport.getOrganizations();
		List<GenericSeverity> severitiesAboveThreshold = getGenericSeveritiesAboveThreshold(scheduledEmailReport);

		List<Object> organizationsModel = list();
		for (Organization organization : organizations){
			List<Object> applicationsModel = getApplicationsModelWithNewVulns(organization, parameters, severitiesAboveThreshold);
			Map<String, Object> organizationTree = map("name", (Object) organization.getName(), "applications", applicationsModel);
			organizationsModel.add(organizationTree);
		}
		return map("organizations", (Object)organizationsModel);
	}

	private List<Object> getApplicationsModelWithNewVulns (Organization organization,
															VulnerabilitySearchParameters parameters,
															List<GenericSeverity> severitiesAboveThreshold) {
		List<Object> applicationsModel = list();
		for (Application application : organization.getApplications()){
			parameters.setApplications(list(application));
			Map<String, Object> severityTreeWithVulns = getSeverityTreeWithVulns(parameters, severitiesAboveThreshold);
			if (!severityTreeWithVulns.isEmpty()){
				Map<String, Object> applicationTree = map("name", (Object) application.getName(),
                        "severityTree", severityTreeWithVulns,
                        "url", application.getUrl());
				applicationsModel.add(applicationTree);
			}
		}
		return applicationsModel;
	}

	private Map<String, Object> getSeverityTreeWithVulns(VulnerabilitySearchParameters parameters, List<GenericSeverity> severitiesAboveThreshold){
		Map<String, Object> severityTreeWithVulns = map();
		for (GenericSeverity genericSeverity : severitiesAboveThreshold){
			parameters.setGenericSeverities(list(genericSeverity));
			List<VulnerabilityTreeElement> tree = vulnerabilitySearchService.getTree(parameters);
			if (!tree.isEmpty()){
				List<Object> treesWithVuln = constructTreeWithVulns(tree, parameters); //loop on trees to retrieve the vulns while the parameters are configured
				severityTreeWithVulns.put(genericSeverity.getName(), treesWithVuln);
			}
		}
		return severityTreeWithVulns;
	}

	private List<Object> constructTreeWithVulns(List<VulnerabilityTreeElement> trees, VulnerabilitySearchParameters parameters) {
		List<Object> treesWithVulns = list();
		for (VulnerabilityTreeElement tree : trees){
			Map<String, Object> treeWithVulns = map();
			//using CWE name to look up generic vuln, uses second pivot because it is defaulted to be the CWE
			GenericVulnerability genericVulnerability = genericVulnerabilityService.loadByName(tree.getSecondaryPivotName());
			parameters.setGenericVulnerabilities(list(genericVulnerability));
			List<Vulnerability> vulnerabilities = vulnerabilitySearchService.performLookup(parameters);//returns 10 vulns max
			treeWithVulns.put("vulnerabilities", vulnerabilities);
			treeWithVulns.put("numResults", tree.getNumResults());
			treeWithVulns.put("genericVulnerability", genericVulnerability);
			treesWithVulns.add(treeWithVulns);
		}
		//cleaning parameters that can be reused by calling function without messing
		parameters.setGenericVulnerabilities(listOf(GenericVulnerability.class));
		return treesWithVulns;
	}

	private List<GenericSeverity> getGenericSeveritiesAboveThreshold(ScheduledEmailReport scheduledEmailReport){
		GenericSeverity severityLevel = scheduledEmailReport.getSeverityLevel();
		List<GenericSeverity> genericSeverities = genericSeverityService.loadAll();
		List<GenericSeverity> genericSeveritiesAboveThreshold = list();
		for (GenericSeverity genericSeverity : genericSeverities){
			if (genericSeverity.getIntValue() >= severityLevel.getIntValue()){
				genericSeveritiesAboveThreshold.add(genericSeverity);
			}
		}
		return genericSeveritiesAboveThreshold;
	}

    @Override
    public void sendPolicyReport(List<PolicyStatus> policyStatuses) {

        if (policyStatusService != null) {
            Map<String, List<PolicyStatus>> emailMap = map();

            for (PolicyStatus policyStatus : policyStatuses) {
                Set<String> filteredEmailAddresses = set();

				if (policyStatus.hasStatusChanged()) {
					filteredEmailAddresses = emailFilterService.getFilteredEmailAddresses(
							policyStatusService.getNotificationEmailAddresses(policyStatus));
				}

                LOG.info("Filtered email addresses: " + filteredEmailAddresses.toString());

                for (String email : filteredEmailAddresses) {
                    if (!emailMap.containsKey(email)) {
                        emailMap.put(email, CollectionUtils.<PolicyStatus>list());
                    }
                    emailMap.get(email).add(policyStatus);
                }
            }

            if(emailMap.size() == 0)
                return;

            for (Map.Entry<String, List<PolicyStatus>> entry : emailMap.entrySet()) {
                String emailAddress = entry.getKey();
                List<PolicyStatus> statuses = entry.getValue();

                Map<String, Object> model = map();
                model.put("statuses", statuses);

                String emailBody = templateBuilderService.prepareMessageFromTemplate(model, "policyReport.vm");
                MimeMessage message = javaMailSender.createMimeMessage();

                try {
                    message.setSubject("Policy Status Update");
                    message.setContent(emailBody, "text/html; charset=utf-8");
                    message.addRecipient(MimeMessage.RecipientType.TO, new InternetAddress(emailAddress));
                } catch (MessagingException e) {
                    e.printStackTrace();
                }

                try {
                    javaMailSender.send(message);
                    LOG.info("Email report sent normally sent normally");
                } catch (MailException ex) {
                    LOG.error("Email not send because of misconfiguration", ex);
                }
            }
        }
    }
}
