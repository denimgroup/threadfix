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
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/defects")
@SessionAttributes("defectViewModel")
public class DefectsController {
	
	public DefectsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(DefectsController.class);

	private ApplicationService applicationService;
	private PermissionService permissionService;
	private QueueSender queueSender;

	@Autowired
	public DefectsController(ApplicationService applicationService, 
			PermissionService permissionService,
			QueueSender queueSender) {
		this.queueSender = queueSender;
		this.permissionService = permissionService;
		this.applicationService = applicationService;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String onSubmit(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			@ModelAttribute DefectViewModel defectViewModel, ModelMap model,
			HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.CAN_SUBMIT_DEFECTS, orgId, appId)) {
			return "403";
		}
		
		if (defectViewModel.getVulnerabilityIds() == null
				|| defectViewModel.getVulnerabilityIds().size() == 0) {
			log.info("No vulnerabilities selected for Defect submission.");
			String message = "You must select at least one vulnerability.";
			ControllerUtils.addErrorMessage(request, message);
			model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
			return "ajaxRedirectHarness";
		}

		queueSender.addSubmitDefect(defectViewModel.getVulnerabilityIds(),
				defectViewModel.getSummary(), defectViewModel.getPreamble(),
				defectViewModel.getSelectedComponent(), defectViewModel.getVersion(),
				defectViewModel.getSeverity(), defectViewModel.getPriority(),
				defectViewModel.getStatus(), orgId, appId);
		
		ControllerUtils.addSuccessMessage(request, "Defect Submission was added to the queue.");
		model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
		return "ajaxRedirectHarness";
	}

	@RequestMapping(value = "/update", method = RequestMethod.GET)
	public String updateVulnsFromDefectTracker(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || app.getOrganization() == null || app.getOrganization().getId() == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		queueSender.addDefectTrackerVulnUpdate(orgId, appId);
		
		ControllerUtils.addSuccessMessage(request, 
				"The Defect Tracker update was successfully added to the queue for processing.");

		return "redirect:/organizations/" + app.getOrganization().getId() + 
				"/applications/" + app.getId();
	}
}
