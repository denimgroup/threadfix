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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.support.SessionStatus;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
	@Autowired
	protected ChannelVulnerabilityService channelVulnerabilityService;
	@Autowired
	protected ChannelTypeService channelTypeService;
	@Autowired
	protected ChannelVulnerabilityFilterService channelVulnerabilityFilterService;

	private final SanitizedLogger log = new SanitizedLogger(AbstractVulnFilterController.class);
	private static final String
		SUCCESS_MESSAGE = "Vulnerability Filter settings saved successfully.",
		FAILURE_MESSAGE = "Vulnerability Filter settings were not saved successfully.",
        AUTHORIZATION_FAILED = "You are not authorized to perform actions on this filter.";


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
		if (appId != -1) {
			return "Application";
		} else if (orgId != -1) {
			return "Organization";
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
				filter.setOrganization(organizationService.loadById(orgId));
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
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return "403";
		}

		model.addAttribute("isEnterprise", EnterpriseTest.isEnterprise());
		model.addAttribute("vulnerabilityFilter", vulnerabilityFilterService.getNewFilter(orgId, appId));
		model.addAttribute("severityFilter",      getSeverityFilter(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		return "filters/index";
	}

	public RestResponse<Map<String, Object>> mapBackend(int orgId, int appId) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return RestResponse.failure("You don't have permission to edit these filters.");
		}

        Map<String, Object> map = new HashMap<>();

        String type = getType(orgId, appId);

        map.put("application", applicationService.loadApplication(appId));
        map.put("organization", organizationService.loadById(orgId));
		map.put("vulnerabilityFilter", vulnerabilityFilterService.getNewFilter(orgId, appId));
		map.put("globalSeverityFilter", getSeverityFilter(-1, -1));
		map.put("globalVulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(-1, -1));
		map.put("type", type);
		map.put("originalType", type);
		map.put("genericSeverities", getGenericSeverities());
		map.put("genericVulnerabilities", getGenericVulnerabilities());

		if (!type.equals("Global")) {
			map.put("teamSeverityFilter", getSeverityFilter(orgId, -1));
			map.put("teamVulnerabilityFilters", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, -1));
		}

		if (EnterpriseTest.isEnterprise()) {
			List<ChannelType> channelTypes = channelTypeService.loadAll();
			map.put("channelVulnerabilitiesMap", channelVulnerabilityService.getChannelVulnsEachChannelType(channelTypes));
			map.put("channelTypes", channelTypes);
			map.put("globalChannelVulnFilterList", channelVulnerabilityFilterService.retrieveAll());
		}

		if (type.equals("Application")) {
			map.put("applicationSeverityFilter", getSeverityFilter(orgId, appId));
			map.put("applicationVulnerabilityFilters", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		}

		return RestResponse.success(map);
	}
	
	public String tabBackend(Model model, int orgId, int appId) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return "403";
		}
		
		model.addAttribute("vulnerabilityFilter",     vulnerabilityFilterService.getNewFilter(orgId, appId));
		model.addAttribute("severityFilter",          getSeverityFilter(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		model.addAttribute("contentPage", "filters/tab.jsp");
		return "ajaxSuccessHarness";
	}

	public RestResponse<VulnerabilityFilter> submitNewBackend(
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			int orgId,
			int appId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return RestResponse.failure(AUTHORIZATION_FAILED);
		}

		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));

		if (!bindingResult.hasErrors()) {
			vulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult);
		}
		
		if (bindingResult.hasErrors()) {
			log.warn(FAILURE_MESSAGE);
            return FormRestResponse.failure(FAILURE_MESSAGE, bindingResult);
		} else {
			vulnerabilityFilterService.save(vulnerabilityFilter, orgId, appId);
			vulnerabilityFilterService.updateStatistics(orgId, appId);
			status.setComplete();
			log.info(SUCCESS_MESSAGE);
            return RestResponse.success(vulnerabilityFilter);
		}
	}

	public RestResponse<VulnerabilityFilter> submitEditBackend(
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			int orgId,
			int appId,
			int filterId) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return RestResponse.failure(AUTHORIZATION_FAILED);
		}
		
		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		
		if (!bindingResult.hasErrors()) {
			vulnerabilityFilter = vulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult, filterId);
		}

        if (bindingResult.hasErrors()) {
            log.warn(FAILURE_MESSAGE);
            return FormRestResponse.failure("Found some errors", bindingResult);
        } else {
            vulnerabilityFilter.setId(filterId);
            vulnerabilityFilterService.save(vulnerabilityFilter, orgId, appId);
			vulnerabilityFilterService.updateStatistics(orgId, appId);
            status.setComplete();
            log.info(SUCCESS_MESSAGE);
            return RestResponse.success(vulnerabilityFilter);
        }
	}
	
	public String submitDeleteBackend(Model model, int orgId, int appId, int filterId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, orgId, appId)) {
			return "403";
		}
		
		vulnerabilityFilterService.delete(filterId, orgId, appId);
		
		log.info("Vulnerability Filter was successfully deleted");
		model.addAttribute("successMessage", "Vulnerability Filter was successfully deleted");
		return returnSuccess(model, orgId, appId);
	}

	public RestResponse<ChannelVulnerabilityFilter> submitNewChannelFilterBackend(
			ChannelVulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, -1, -1)) {
			return RestResponse.failure(AUTHORIZATION_FAILED);
		}


		if (!bindingResult.hasErrors()) {
			channelVulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult, -1);
		}

		if (bindingResult.hasErrors()) {
			log.warn(FAILURE_MESSAGE);
			return FormRestResponse.failure(FAILURE_MESSAGE, bindingResult);
		} else {
			channelVulnerabilityFilterService.save(vulnerabilityFilter);
			channelVulnerabilityFilterService.updateStatistics();
			status.setComplete();
			log.info(SUCCESS_MESSAGE);
			return RestResponse.success(vulnerabilityFilter);
		}
	}

	public RestResponse<ChannelVulnerabilityFilter> submitEditChannelFilterBackend(
			ChannelVulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			int filterId) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, -1, -1)) {
			return RestResponse.failure(AUTHORIZATION_FAILED);
		}

		if (!bindingResult.hasErrors()) {
			vulnerabilityFilter = channelVulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult, filterId);
		}

		if (bindingResult.hasErrors()) {
			log.warn(FAILURE_MESSAGE);
			return FormRestResponse.failure("Found some errors", bindingResult);
		} else {
			vulnerabilityFilter.setId(filterId);
			channelVulnerabilityFilterService.save(vulnerabilityFilter);
			channelVulnerabilityFilterService.updateStatistics();
			status.setComplete();
			log.info(SUCCESS_MESSAGE);
			return RestResponse.success(vulnerabilityFilter);
		}
	}

	public String submitDeleteChannelFilterBackend(int filterId) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, -1, -1)) {
			return "403";
		}
		channelVulnerabilityFilterService.delete(filterId);

		String msg = "Channel Vulnerability Filter was successfully deleted";
		log.info(msg);
		return msg;
	}
	
	public String returnSuccess(Model model, int orgId, int appId) {
		model.addAttribute("vulnerabilityFilter", new VulnerabilityFilter());
		model.addAttribute("vulnerabilityFilterList", vulnerabilityFilterService.getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		model.addAttribute("contentPage", "filters/table.jsp");
		return "ajaxSuccessHarness";
	}
}
