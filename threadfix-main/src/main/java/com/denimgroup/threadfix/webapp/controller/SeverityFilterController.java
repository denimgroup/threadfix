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

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.VulnerabilityFilterService;

@Controller
@SessionAttributes("severityFilter")
public class SeverityFilterController {
	
	public SeverityFilterService severityFilterService;
	public OrganizationService organizationService;
	public ApplicationService applicationService;
	public VulnerabilityFilterService vulnerabilityFilterService;
	public PermissionService permissionService;
	public GenericVulnerabilityService genericVulnerabilityService;
	public GenericSeverityService genericSeverityService;
	
	private final SanitizedLogger log = new SanitizedLogger(SeverityFilterController.class);
	
	@Autowired
	public SeverityFilterController(
			GenericSeverityService genericSeverityService,
			GenericVulnerabilityService genericVulnerabilityService,
			PermissionService permissionService,
			VulnerabilityFilterService vulnerabilityFilterService,
			OrganizationService organizationService,
			ApplicationService applicationService,
			SeverityFilterService severityFilterService) {
		this.severityFilterService = severityFilterService;
		this.vulnerabilityFilterService = vulnerabilityFilterService;
		this.applicationService = applicationService;
		this.organizationService = organizationService;
		this.permissionService = permissionService;
		this.genericSeverityService = genericSeverityService;
		this.genericVulnerabilityService = genericVulnerabilityService;
	}
	
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
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("showInfo", "showLow", "showMedium", "showHigh",
				"showCritical", "id", "global", "enabled", "organization.id", "application.id");
	}
	
	@RequestMapping(value = "/configuration/severityFilter/set", method = RequestMethod.POST)
	public String setGlobalSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			HttpServletRequest request) {

		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, null, null)) {
			return "403";
		}
		
		return doSet(severityFilter, bindingResult, status, model, -1, -1, request);
	}
	
	@RequestMapping(value = "/organizations/{orgId}/severityFilter/set", method = RequestMethod.POST)
	public String setApplicationSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			HttpServletRequest request, @PathVariable int orgId) {

		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
			return "403";
		}
		
		return doSet(severityFilter, bindingResult, status, model, orgId, -1, request);
	}
	
	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/severityFilter/set", method = RequestMethod.POST)
	public String setTeamSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			@PathVariable int appId, @PathVariable int orgId,
			HttpServletRequest request) {

		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		return doSet(severityFilter, bindingResult, status, model, orgId, appId, request);
	}
	
	private String doSet(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			int orgId, int appId,
			HttpServletRequest request) {
		
		String returnPage = null;
		
		if (bindingResult.hasErrors()) {
			
			model.addAttribute("contentPage", "filters/severityFilterForm.jsp");
			returnPage = "ajaxFailureHarness";
			log.warn("Severity Filter settings were not saved successfully.");
			
		} else {
			updateSeverityFilter(severityFilter, orgId, appId);
			severityFilterService.clean(severityFilter, orgId, appId);
			severityFilterService.save(severityFilter, orgId, appId);
			vulnerabilityFilterService.updateVulnerabilities(orgId, appId);
			
			log.info("Severity Filter settings saved successfully.");
			returnPage = returnSuccess(model, orgId, appId);
		}
		
		return returnPage;
	}
	
	private void updateSeverityFilter(SeverityFilter severityFilter, int orgId, int appId) {
		
		if (severityFilter != null) {
			if (orgId == -1 && appId == -1) {
				severityFilter.setGlobal(true);
				severityFilter.setApplication(null);
				severityFilter.setOrganization(null);
			} else if (appId != -1) {
				severityFilter.setGlobal(false);
				severityFilter.setApplication(applicationService.loadApplication(appId));
				severityFilter.setOrganization(null);
			} else {
				severityFilter.setGlobal(false);
				severityFilter.setApplication(null);
				severityFilter.setOrganization(organizationService.loadOrganization(orgId));
			}
		}
	}
	
	public String returnSuccess(Model model, int orgId, int appId) {
		model.addAttribute("vulnerabilityFilter", vulnerabilityFilterService.getNewFilter(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		model.addAttribute("severitySuccessMessage", "Severity Filter settings saved successfully.");
		model.addAttribute("contentPage", "filters/tab.jsp");
		return "ajaxSuccessHarness";
	}
	
	public String getType(int orgId, int appId) {
		if (orgId == -1 && appId == -1) {
			return "Global";
		} else if (appId != -1) {
			return "Application";
		} else {
			return "Organization";
		}
	}
}
