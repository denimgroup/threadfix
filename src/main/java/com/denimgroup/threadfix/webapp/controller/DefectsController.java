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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.ProjectMetadata;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/defects")
@SessionAttributes("defectViewModel")
public class DefectsController {
	
	private final Log log = LogFactory.getLog(DefectsController.class);

	private ApplicationService applicationService;
	private QueueSender queueSender;

	@Autowired
	public DefectsController(ApplicationService applicationService, QueueSender queueSender) {
		this.queueSender = queueSender;
		this.applicationService = applicationService;
	}

	@ModelAttribute("projectMetadata")
	public ProjectMetadata populateprojectMetadata(@PathVariable("appId") int appId) {
		Application application = applicationService.loadApplication(appId);
		AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
		return dt.getProjectMetadata();
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView defectList(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			ModelMap model) {
		return defectSubmissionPage(orgId, appId, null);
	}
	
	private ModelAndView defectSubmissionPage(int orgId, int appId, String message) {
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView modelAndView = new ModelAndView("defects/index");

		modelAndView.addObject("message", message);
		modelAndView.addObject(new DefectViewModel());
		modelAndView.addObject(application);
		return modelAndView;
	}

	@RequestMapping(method = RequestMethod.POST)
	public ModelAndView onSubmit(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			@ModelAttribute DefectViewModel defectViewModel, ModelMap model) {
		
		if (defectViewModel.getVulnerabilityIds() == null
				|| defectViewModel.getVulnerabilityIds().size() == 0) {
			log.info("No vulnerabilities selected for Defect submission.");
			String message = "You must select at least one vulnerability";
			return defectSubmissionPage(orgId, appId, message);
		}

		queueSender.addSubmitDefect(defectViewModel.getVulnerabilityIds(),
				defectViewModel.getSummary(), defectViewModel.getPreamble(),
				defectViewModel.getSelectedComponent(), defectViewModel.getVersion(),
				defectViewModel.getSeverity(), defectViewModel.getPriority(),
				defectViewModel.getStatus(), orgId, appId);
		return new ModelAndView("redirect:/jobs/open");
	}

	@RequestMapping(value = "/update", method = RequestMethod.GET)
	public String updateVulnsFromDefectTracker(@PathVariable("appId") int appId) {
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || app.getOrganization() == null || app.getOrganization().getId() == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		Integer orgId = app.getOrganization().getId();
		queueSender.addDefectTrackerVulnUpdate(orgId, appId);
		return "redirect:/jobs/open";
	}
}
