////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.support.SessionStatus;

import java.util.List;

public abstract class AbstractVulnFilterController {

    @Autowired
	protected VulnerabilityFilterService vulnerabilityFilterService;
    @Autowired
	protected SeverityFilterService severityFilterService;
    @Autowired
	protected GenericVulnerabilityService genericVulnerabilityService;
    @Autowired
	protected GenericSeverityService genericSeverityService;
    @Autowired
	protected ApplicationService applicationService;
    @Autowired
	protected OrganizationService organizationService;

	private final SanitizedLogger log = new SanitizedLogger(AbstractVulnFilterController.class);
	private static final String
		SUCCESS_MESSAGE = "Vulnerability Filter settings saved successfully.",
		FAILURE_MESSAGE = "Vulnerability Filter settings were not saved successfully.";
	
	@ModelAttribute("genericVulnerabilities")
	public List<GenericVulnerability> getGenericVulnerabilities() {
		return genericVulnerabilityService.loadAll();
	}
	
	@ModelAttribute("genericSeverities")
	public List<GenericSeverity> getGenericSeverities() {
		List<GenericSeverity> severities = genericSeverityService.loadAll();
		
		GenericSeverity ignoreSeverity = new GenericSeverity();
		ignoreSeverity.setId(-1);
		ignoreSeverity.setName("Ignore");
		severities.add(ignoreSeverity);
		
		return severities;
	}
	
	public String getType(int orgId, int appId) {
		if (orgId != -1) {
			return "Organization";
		} else if (appId != -1) {
			return "Application";
		} else {
			return "Global";
		}
	}
	
	private SeverityFilter getSeverityFilter(int orgId, int appId) {
		SeverityFilter filter = severityFilterService.loadFilter(orgId, appId);
		
		boolean shouldInherit = filter == null || !filter.getEnabled();
		
		if (filter == null) {
			filter = new SeverityFilter();
			if (appId != -1) {
				filter.setApplication(applicationService.loadApplication(appId));
			} else if (orgId != -1) {
				filter.setOrganization(organizationService.loadOrganization(orgId));
			} else {
				filter.setGlobal(true);
			}
		}
		
		if (shouldInherit) {
			filter.setFilters(severityFilterService.getParentFilter(orgId, appId));
		}
		
		return filter;
	}

	public String indexBackend(Model model, int orgId, int appId) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		model.addAttribute("vulnerabilityFilter", vulnerabilityFilterService.getNewFilter(orgId, appId));
		model.addAttribute("severityFilter",      getSeverityFilter(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		return "filters/index";
	}
	
	public String tabBackend(Model model, int orgId, int appId) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		model.addAttribute("vulnerabilityFilter",     vulnerabilityFilterService.getNewFilter(orgId, appId));
		model.addAttribute("severityFilter",          getSeverityFilter(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		model.addAttribute("contentPage", "filters/tab.jsp");
		return "ajaxSuccessHarness";
	}

	public String submitNewBackend(
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			Model model,
			int orgId,
			int appId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}

		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		
		String responsePage;
		
		if (!bindingResult.hasErrors()) {
			vulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult);
		}
		
		if (bindingResult.hasErrors()) {
			model.addAttribute("contentPage", "filters/newForm.jsp");
			responsePage = "ajaxFailureHarness";
			log.warn(FAILURE_MESSAGE);
		} else {
			vulnerabilityFilterService.save(vulnerabilityFilter, orgId, appId);
			status.setComplete();
			responsePage = returnSuccess(model, orgId, appId);
			model.addAttribute("successMessage", SUCCESS_MESSAGE);
			log.info(SUCCESS_MESSAGE);
		}
		
		model.addAttribute("type", getType(orgId, appId));
		return responsePage;
	}

	public String submitEditBackend(
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			Model model,
			int orgId,
			int appId,
			int filterId) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		
		String responsePage;
		
		if (!bindingResult.hasErrors()) {
			vulnerabilityFilter = vulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult, filterId);
		}
		
		if (bindingResult.hasErrors()) {
			model.addAttribute("contentPage", "filters/editForm.jsp");
			model.addAttribute("type", getType(orgId, appId));
			responsePage = "ajaxFailureHarness";
			log.warn(FAILURE_MESSAGE);
		} else {
			vulnerabilityFilter.setId(filterId);
			vulnerabilityFilterService.save(vulnerabilityFilter, orgId, appId);
			status.setComplete();
			responsePage = returnSuccess(model, orgId, appId);
			model.addAttribute("successMessage", SUCCESS_MESSAGE);
		}
		
		return responsePage;
	}
	
	public String submitDeleteBackend(Model model, int orgId, int appId, int filterId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		vulnerabilityFilterService.delete(filterId, orgId, appId);
		
		log.info("Vulnerability Filter was successfully deleted");
		model.addAttribute("successMessage", "Vulnerability Filter was successfully deleted");
		return returnSuccess(model, orgId, appId);
	}
	
	public String returnSuccess(Model model, int orgId, int appId) {
		model.addAttribute("vulnerabilityFilter", new VulnerabilityFilter());
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		model.addAttribute("contentPage", "filters/table.jsp");
		return "ajaxSuccessHarness";
	}
}
