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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SeverityFilterService;

@Controller
@SessionAttributes("severityFilter")
public class SeverityFilterController {
	
	public SeverityFilterService severityFilterService;
	public OrganizationService organizationService;
	public ApplicationService applicationService;
	
	@Autowired
	public SeverityFilterController(OrganizationService organizationService,
			ApplicationService applicationService,
			SeverityFilterService severityFilterService) {
		this.severityFilterService = severityFilterService;
		this.applicationService = applicationService;
		this.organizationService = organizationService;
	}
	
	@RequestMapping(value = "/configuration/severityFilter/set", method = RequestMethod.POST)
	public String setGlobalSeverityFilters(@ModelAttribute SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model) {
		
		String returnPage = null;
		
		if (bindingResult.hasErrors()) {
			
			model.addAttribute("contentPage", "filters/severityFilterForm.jsp");
			returnPage = "ajaxFailureHarness";
			
		} else {
			severityFilter.setGlobal(true);
			severityFilter.setOrganization(null);
			severityFilter.setApplication(null);
			severityFilterService.clean(severityFilter, -1, -1);
			severityFilterService.save(severityFilter);
			
			model.addAttribute("contentPage", "/configuration/filters");
			returnPage = "ajaxRedirectHarness";
		}
		
		return returnPage;
	}
	
	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/severityFilter/set", method = RequestMethod.POST)
	public String setTeamSeverityFilters(@ModelAttribute SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			@PathVariable int appId, @PathVariable int orgId) {
		
		String returnPage = null;
		
		if (bindingResult.hasErrors()) {
			
			model.addAttribute("contentPage", "filters/severityFilterForm.jsp");
			returnPage = "ajaxFailureHarness";
			
		} else {
			severityFilter.setGlobal(false);
			severityFilter.setOrganization(null);
			severityFilter.setApplication(applicationService.loadApplication(appId));
			severityFilterService.clean(severityFilter, orgId, appId);
			severityFilterService.save(severityFilter);
			
			model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/filters");
			returnPage = "ajaxRedirectHarness";
		}
		
		return returnPage;
	}
	
	@RequestMapping(value = "/organizations/{orgId}/severityFilter/set", method = RequestMethod.POST)
	public String setApplicationSeverityFilters(@ModelAttribute SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model, @PathVariable int orgId) {
		
		String returnPage = null;
		
		if (bindingResult.hasErrors()) {
			
			model.addAttribute("contentPage", "filters/severityFilterForm.jsp");
			returnPage = "ajaxFailureHarness";
			
		} else {
			severityFilter.setGlobal(false);
			severityFilter.setOrganization(organizationService.loadOrganization(orgId));
			severityFilter.setApplication(null);
			severityFilterService.clean(severityFilter, orgId, -1);
			severityFilterService.save(severityFilter);
			
			model.addAttribute("contentPage", "/organizations/" + orgId + "/filters");
			returnPage = "ajaxRedirectHarness";
		}
		
		return returnPage;
	}

}
