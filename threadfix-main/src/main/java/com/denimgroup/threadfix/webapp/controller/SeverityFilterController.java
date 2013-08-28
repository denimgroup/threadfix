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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
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
	
	private final SanitizedLogger log = new SanitizedLogger(SeverityFilterController.class);
	
	@Autowired
	public SeverityFilterController(
			VulnerabilityFilterService vulnerabilityFilterService,
			OrganizationService organizationService,
			ApplicationService applicationService,
			SeverityFilterService severityFilterService) {
		this.severityFilterService = severityFilterService;
		this.vulnerabilityFilterService = vulnerabilityFilterService;
		this.applicationService = applicationService;
		this.organizationService = organizationService;
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
		String page = doSet(severityFilter, bindingResult, status, model, -1, -1, request);
		model.addAttribute("contentPage", "/configuration/filters");
		return page;
	}
	
	@RequestMapping(value = "/organizations/{orgId}/severityFilter/set", method = RequestMethod.POST)
	public String setApplicationSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			HttpServletRequest request, @PathVariable int orgId) {
		String page = doSet(severityFilter, bindingResult, status, model, orgId, -1, request);
		model.addAttribute("contentPage", "/organizations/" + orgId + "/filters");
		return page;
	}
	
	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/severityFilter/set", method = RequestMethod.POST)
	public String setTeamSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			@PathVariable int appId, @PathVariable int orgId,
			HttpServletRequest request) {
		String page = doSet(severityFilter, bindingResult, status, model, orgId, appId, request);
		model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/filters");
		return page;
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
			
			ControllerUtils.addSuccessMessage(request, "Severity Filter settings saved successfully.");
			log.info("Severity Filter settings saved successfully.");
			returnPage = "ajaxRedirectHarness";
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
}
