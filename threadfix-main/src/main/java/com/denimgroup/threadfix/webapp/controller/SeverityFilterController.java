////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
public class SeverityFilterController {

    @Autowired
	public SeverityFilterService severityFilterService;
    @Autowired
	public OrganizationService organizationService;
    @Autowired
	public ApplicationService applicationService;
    @Autowired
	public VulnerabilityFilterService vulnerabilityFilterService;
    @Autowired
	public GenericVulnerabilityService genericVulnerabilityService;
    @Autowired
	public GenericSeverityService genericSeverityService;
    @Autowired
    private QueueSender queueSender = null;
	
	private final SanitizedLogger log = new SanitizedLogger(SeverityFilterController.class);

	
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
	
	@RequestMapping(value = "/configuration/filters/severityFilter/set", method = RequestMethod.POST)
	public @ResponseBody RestResponse<SeverityFilter> setGlobalSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, null, null)) {
			return RestResponse.failure("You are not authorized to edit this filter.");
		}

		return doSet(severityFilter, bindingResult, -1, -1);
	}

	@RequestMapping(value = "/organizations/{orgId}/filters/severityFilter/set", method = RequestMethod.POST)
	public @ResponseBody RestResponse<SeverityFilter> setApplicationSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, @PathVariable int orgId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, null)) {
			return RestResponse.failure("You are not authorized to edit this filter.");
		}

		return doSet(severityFilter, bindingResult, orgId, -1);
	}

	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/filters/severityFilter/set", method = RequestMethod.POST)
	public @ResponseBody RestResponse<SeverityFilter> setTeamSeverityFilters(SeverityFilter severityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			@PathVariable int appId, @PathVariable int orgId,
			HttpServletRequest request) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return RestResponse.failure("You are not authorized to edit this filter.");
		}

		return doSet(severityFilter, bindingResult, orgId, appId);
	}
	
	private RestResponse<SeverityFilter> doSet(SeverityFilter severityFilter,
			BindingResult bindingResult, int orgId, int appId) {
		
		if (bindingResult.hasErrors()) {
			log.warn("Severity Filter settings were not saved successfully.");

            return RestResponse.failure("Errors: " + bindingResult.getAllErrors());

		} else {
			updateSeverityFilter(severityFilter, orgId, appId);
			severityFilterService.clean(severityFilter, orgId, appId);
			severityFilterService.save(severityFilter, orgId, appId);
			vulnerabilityFilterService.updateVulnerabilities(orgId, appId);

	    	return RestResponse.success(severityFilter);
		}
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
				severityFilter.setOrganization(organizationService.loadById(orgId));
			}
		}
	}
}
