////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.ProjectMetadata;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/defects")
@SessionAttributes("defectViewModel")
public class DefectsController {
	
	public DefectsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(DefectsController.class);

	private ApplicationService applicationService;
	private OrganizationService organizationService;
	private QueueSender queueSender;

	@Autowired
	public DefectsController(ApplicationService applicationService, 
			OrganizationService organizationService,
			QueueSender queueSender) {
		this.queueSender = queueSender;
		this.organizationService = organizationService;
		this.applicationService = applicationService;
	}

	@RequestMapping(method = RequestMethod.GET)
	@PreAuthorize("hasRole('ROLE_CAN_SUBMIT_DEFECTS')")
	public ModelAndView defectList(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			ModelMap model, HttpServletRequest request) {
		
		return defectSubmissionPage(orgId, appId, null, request);
	}
	
	private ModelAndView defectSubmissionPage(int orgId, int appId, String message,
			HttpServletRequest request) {
		
		if (!organizationService.isAuthorized(orgId)) {
			return new ModelAndView("403");
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView modelAndView = new ModelAndView("defects/index");
		
		if (application != null) {
			applicationService.decryptCredentials(application);
		}

		AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
		ProjectMetadata data = null;

		if (dt != null) {
			data = dt.getProjectMetadata();
		}
		
		if (data == null || data.getComponents() == null || 
				data.getComponents().size() == 0) {
			request.getSession().setAttribute("scanErrorMessage", 
					"No components were found for the configured Defect Tracker project. " +
					"Please configure your project so that is has a component.");
			return new ModelAndView("redirect:/organizations/" + orgId + "/applications/" + appId);
		}
		
		modelAndView.addObject("projectMetadata", data);
		modelAndView.addObject("message", message);
		modelAndView.addObject(new DefectViewModel());
		modelAndView.addObject(application);
		return modelAndView;
	}

	@PreAuthorize("hasRole('ROLE_CAN_SUBMIT_DEFECTS')")
	@RequestMapping(method = RequestMethod.POST)
	public ModelAndView onSubmit(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			@ModelAttribute DefectViewModel defectViewModel, ModelMap model,
			HttpServletRequest request) {
		
		if (!organizationService.isAuthorized(orgId)) {
			return new ModelAndView("403");
		}
		
		if (defectViewModel.getVulnerabilityIds() == null
				|| defectViewModel.getVulnerabilityIds().size() == 0) {
			log.info("No vulnerabilities selected for Defect submission.");
			String message = "You must select at least one vulnerability";
			return defectSubmissionPage(orgId, appId, message, request);
		}

		queueSender.addSubmitDefect(defectViewModel.getVulnerabilityIds(),
				defectViewModel.getSummary(), defectViewModel.getPreamble(),
				defectViewModel.getSelectedComponent(), defectViewModel.getVersion(),
				defectViewModel.getSeverity(), defectViewModel.getPriority(),
				defectViewModel.getStatus(), orgId, appId);
		return new ModelAndView("redirect:/jobs/open");
	}

	@RequestMapping(value = "/update", method = RequestMethod.GET)
	public String updateVulnsFromDefectTracker(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			HttpServletRequest request) {
		
		if (!organizationService.isAuthorized(orgId)) {
			return "403";
		}
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || app.getOrganization() == null || app.getOrganization().getId() == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		queueSender.addDefectTrackerVulnUpdate(orgId, appId);
		
		request.getSession().setAttribute("queueSuccessMessage", 
				"The Defect Tracker update was successfully added to the queue for processing.");
		return "redirect:/organizations/" + app.getOrganization().getId() + 
				"/applications/" + app.getId();
	}
}
