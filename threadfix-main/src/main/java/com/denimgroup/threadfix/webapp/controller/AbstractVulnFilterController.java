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

import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.data.entities.VulnerabilityFilter;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.VulnerabilityFilterService;

public abstract class AbstractVulnFilterController {
	
	protected VulnerabilityFilterService vulnerabilityFilterService;
	protected SeverityFilterService severityFilterService;
	protected GenericVulnerabilityService genericVulnerabilityService;
	protected GenericSeverityService genericSeverityService;
	protected ApplicationService applicationService;
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
	
	public VulnerabilityFilter getNewFilter(int orgId, int appId) {
		VulnerabilityFilter vulnerabilityFilter = new VulnerabilityFilter();
		if (appId != -1) {
			vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		} else if (orgId != -1) {
			vulnerabilityFilter.setOrganization(organizationService.loadOrganization(orgId));
		} else {
			vulnerabilityFilter.setGlobal(true);
		}
		return vulnerabilityFilter;
	}
	
	public List<VulnerabilityFilter> getPrimaryVulnerabilityList(int orgId, int appId) {
		List<VulnerabilityFilter> filters;
		if (appId != -1) {
			filters = vulnerabilityFilterService.loadAllApplication(appId);
		} else if (orgId != -1) {
			filters = vulnerabilityFilterService.loadAllOrganization(orgId);
		} else {
			filters = vulnerabilityFilterService.loadAllGlobal();
		}
		return filters;
	}
	
	private List<VulnerabilityFilter> getGlobalList(int orgId, int appId) {
		if (orgId != -1 || appId != -1) {
			return vulnerabilityFilterService.loadAllGlobal();
		} else {
			return null;
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
	
	private List<VulnerabilityFilter> getTeamFilters(int orgId, int appId) {
		if (appId != -1) {
			Application app = applicationService.loadApplication(appId);
			if (app != null && app.getOrganization() != null && app.getOrganization().getId() != null) {
				return vulnerabilityFilterService.loadAllOrganization(app.getOrganization().getId());
			}
		}
		
		return null;
	}

	public AbstractVulnFilterController(
			SeverityFilterService severityFilterService,
			OrganizationService organizationService,
			VulnerabilityFilterService vulnerabilityFilterService,
			ApplicationService applicationService,
			GenericVulnerabilityService genericVulnerabilityService,
			GenericSeverityService genericSeverityService) {
		this.severityFilterService = severityFilterService;
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.vulnerabilityFilterService = vulnerabilityFilterService;
		this.genericVulnerabilityService = genericVulnerabilityService;
		this.genericSeverityService = genericSeverityService;
	}

	public String indexBackend(Model model, int orgId, int appId) {
		model.addAttribute("vulnerabilityFilter", getNewFilter(orgId, appId));
		model.addAttribute("teamFilterList",      getTeamFilters(orgId, appId));
		model.addAttribute("severityFilter",      getSeverityFilter(orgId, appId));
		model.addAttribute("globalFilterList",    getGlobalList(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		return "filters/index";
	}

	public String submitNewBackend(
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			Model model,
			HttpServletRequest request,
			int orgId,
			int appId) {

		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		
		String responsePage = null;
		
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
			ControllerUtils.addSuccessMessage(request, SUCCESS_MESSAGE);
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
			HttpServletRequest request,
			int orgId,
			int appId,
			int filterId) {
		
		vulnerabilityFilter.setApplication(applicationService.loadApplication(appId));
		
		String responsePage = null;
		
		if (!bindingResult.hasErrors()) {
			vulnerabilityFilter = vulnerabilityFilterService.validate(vulnerabilityFilter, bindingResult, filterId);
		}
		
		if (bindingResult.hasErrors()) {
			model.addAttribute("contentPage", "filters/newForm.jsp");
			model.addAttribute("type", getType(orgId, appId));
			responsePage = "ajaxFailureHarness";
			log.warn(FAILURE_MESSAGE);
		} else {
			vulnerabilityFilter.setId(filterId);
			vulnerabilityFilterService.save(vulnerabilityFilter, orgId, appId);
			status.setComplete();
			responsePage = returnSuccess(model, orgId, appId);
			ControllerUtils.addSuccessMessage(request, SUCCESS_MESSAGE);
		}
		
		return responsePage;
	}
	
	public String submitDeleteBackend(Model model,
			HttpServletRequest request, int orgId, int appId, int filterId) {
		
		vulnerabilityFilterService.delete(filterId, orgId, appId);
		
		log.info("Vulnerability Filter was successfully deleted");
		ControllerUtils.addSuccessMessage(request, "Vulnerability Filter was successfully deleted");
		return returnSuccess(model, orgId, appId);
	}
	
	public String returnSuccess(Model model, int orgId, int appId) {
		model.addAttribute("vulnerabilityFilter", new VulnerabilityFilter());
		model.addAttribute("contentPage", "filters/table.jsp");
		model.addAttribute("teamFilterList",   getTeamFilters(orgId, appId));
		model.addAttribute("globalFilterList", getGlobalList(orgId, appId));
		model.addAttribute("vulnerabilityFilterList", getPrimaryVulnerabilityList(orgId, appId));
		model.addAttribute("type", getType(orgId, appId));
		return "ajaxSuccessHarness";
	}
}
