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

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.FalsePositiveModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications")
public class ApplicationsController {
	
	private final Log log = LogFactory.getLog(ApplicationsController.class);

	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private VulnerabilityService vulnerabilityService;

	@Autowired
	public ApplicationsController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService, VulnerabilityService vulnerabilityService) {
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.vulnerabilityService = vulnerabilityService;
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@RequestMapping("/{appId}")
	public String detail(@PathVariable("orgId") Integer orgId, @PathVariable("appId") Integer appId,
			ModelMap model, HttpServletRequest request) {
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		int falsePositives = 0;
		
		Object message = null;
		if (request.getSession() != null) {
			message = request.getSession().getAttribute("scanSuccessMessage");
			if (message != null) {
				request.getSession().removeAttribute("scanSuccessMessage");
			}
		}
		
		if (application.getVulnerabilities() != null && application.getVulnerabilities().size() > 0) {
			List<Vulnerability> vulns = vulnerabilityService.getFalsePositiveVulns(application);
			if (vulns != null) {
				falsePositives = vulns.size();
			}
		}
		
		model.addAttribute(new FalsePositiveModel());
		model.addAttribute("message", message);
		model.addAttribute(application);
		model.addAttribute("falsePositiveCount", falsePositives);
		return "applications/detail";
	}
	
	@RequestMapping("/{appId}/closedVulnerabilities")
	public String viewClosedVulnerabilities(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			ModelMap model) {
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		model.addAttribute(application);
		return "applications/closedVulns";
	}

	@RequestMapping("/{appId}/delete")
	public String processLinkDelete(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, SessionStatus status) {
		Application application = applicationService.loadApplication(appId);
		if (application != null) {
			if (application.getScans() == null || application.getScans().isEmpty()) {
				applicationService.deleteById(appId);
				status.setComplete();
			} else if (application.isActive()) {
				applicationService.deactivateApplication(application);
				status.setComplete();
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/organizations/" + String.valueOf(orgId);
	}

	@RequestMapping(value = "/jsontest", method = RequestMethod.POST)
	public @ResponseBody String readJson(@RequestBody DefectTrackerBean bean) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(bean
				.getDefectTrackerId());
		AbstractDefectTracker dt = new DefectTrackerFactory().getTrackerByType(defectTracker,
				bean.getUserName(), bean.getPassword());
		if (dt == null) {
			log.warn("Incorrect Defect Tracker credentials submitted.");
			return "Authentication failed";
		}

		return dt.getProductNames();
	}
}