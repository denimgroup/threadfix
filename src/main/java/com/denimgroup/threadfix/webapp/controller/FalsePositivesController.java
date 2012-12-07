////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.webapp.viewmodels.FalsePositiveModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/falsepositives")
@SessionAttributes("defectViewModel")
public class FalsePositivesController {
	
	public FalsePositivesController(){}

	private ApplicationService applicationService;
	private PermissionService permissionService;
	private VulnerabilityService vulnerabilityService;

	private final SanitizedLogger log = new SanitizedLogger(FalsePositivesController.class);

	@Autowired
	public FalsePositivesController(ApplicationService applicationService,
			PermissionService PermissionService,
			VulnerabilityService vulnerabilityService) {
		this.applicationService = applicationService;
		this.vulnerabilityService = vulnerabilityService;
		this.permissionService = PermissionService;
	}

	@RequestMapping(value = "/mark", method = RequestMethod.POST)
	public String onSubmit(
			@ModelAttribute FalsePositiveModel falsePositiveModel,
			@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			ModelMap model, HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}

		if (falsePositiveModel == null
				|| falsePositiveModel.getVulnerabilityIds() == null
				|| falsePositiveModel.getVulnerabilityIds().size() == 0) {
			String error = "You must select at least one vulnerability.";
			request.getSession().setAttribute("scanErrorMessage", error);
			return "redirect:/organizations/" + orgId + "/applications/"
					+ appId;
		}

		vulnerabilityService.markListAsFalsePositive(falsePositiveModel
				.getVulnerabilityIds());

		return "redirect:/organizations/" + orgId + "/applications/" + appId;
	}

	@RequestMapping(value = "/unmark", method = RequestMethod.GET)
	public String defectList(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}

		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application",
					appId));
			throw new ResourceNotFoundException();
		}

		List<Vulnerability> markedVulns = vulnerabilityService
				.getFalsePositiveVulns(application);

		model.addAttribute(new FalsePositiveModel());
		model.addAttribute(application);
		model.addAttribute("vulns", markedVulns);
		model.addAttribute("buttonText", "Mark as not False Positives");
		return "falsepositives/index";
	}

	@RequestMapping(value = "/unmark", method = RequestMethod.POST)
	public String onSubmit2(
			@ModelAttribute FalsePositiveModel falsePositiveModel,
			@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}

		if (falsePositiveModel == null
				|| falsePositiveModel.getVulnerabilityIds() == null
				|| falsePositiveModel.getVulnerabilityIds().size() == 0) {
			String error = "You must select at least one vulnerability.";
			model.addAttribute("scanErrorMessage", error);
			return defectList(orgId, appId, model);
		}

		vulnerabilityService.markListAsNotFalsePositive(falsePositiveModel
				.getVulnerabilityIds());

		return "redirect:/organizations/" + orgId + "/applications/" + appId;
	}
	
	@RequestMapping(value="/table", method = RequestMethod.POST)
	public String getTableVulns(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@RequestBody TableSortBean bean,
			ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}		
		
		bean.setOpen(false);
		bean.setFalsePositive(true);
		
		long numVulns = applicationService.getCount(appId, bean);
		long numPages = (numVulns / 100);
		if (numVulns % 100 == 0) {
			numPages -= 1;
		}
		model.addAttribute("numPages", numPages);
		model.addAttribute("numVulns", numVulns);
		
		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
		
		model.addAttribute("page", bean.getPage());
		model.addAttribute("vulnerabilities", applicationService.getVulnTable(appId, bean));
		model.addAttribute(application);
		return "falsepositives/table";
	}
}
