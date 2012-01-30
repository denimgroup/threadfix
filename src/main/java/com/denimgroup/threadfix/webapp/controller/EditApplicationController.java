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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.Node;
import com.denimgroup.threadfix.webapp.viewmodels.PathTree;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/edit")
@SessionAttributes("application")
public class EditApplicationController {

	private final Log log = LogFactory.getLog(DefectTrackersController.class);
	
	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private WafService wafService;
	private DefectService defectService;
	private ScanMergeService scanMergeService;

	@Autowired
	public EditApplicationController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService, WafService wafService,
			DefectService defectService, ScanMergeService scanMergeService) {
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.wafService = wafService;
		this.defectService = defectService;
		this.scanMergeService = scanMergeService;
	}

	@ModelAttribute("defectTrackerList")
	public List<DefectTracker> populateDefectTrackers() {
		return defectTrackerService.loadAllDefectTrackers();
	}

	@ModelAttribute("wafList")
	public List<Waf> populateWafs() {
		return wafService.loadAll();
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "name", "url", "defectTracker.id", "userName", "password", "waf.id", "projectName", "projectRoot" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView setupForm(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		List<String> pathList = new ArrayList<String>();
		for (Vulnerability vuln : application.getVulnerabilities()) {
			if (vuln != null && vuln.getFindings() != null) {
				for (Finding finding : vuln.getFindings()) {
					if (finding != null && finding.getSourceFileLocation() != null) {
						pathList.add(finding.getSourceFileLocation());
					}
				}
			}
		}
		pathList = removeDuplicates(pathList);
		PathTree pathTree = new PathTree(new Node("root"));
		pathTree = getTreeStructure(pathList, pathTree, application);
		
		ModelAndView mav = new ModelAndView("applications/form");
		mav.addObject(application);
		mav.addObject("pathTree", pathTree);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application,
			BindingResult result, SessionStatus status) {
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
			return "applications/form";
		} else {
			if (application.getWaf() != null && application.getWaf().getId() == 0) {
				application.setWaf(null);
			}
			
			if (application.getWaf() != null && application.getWaf().getId() != null) {
				Waf waf = wafService.loadWaf(application.getWaf().getId());
				
				if (waf == null) {
					result.rejectValue("waf.id", "errors.invalid", new String [] { "WAF Choice" }, null);
				} else {
					application.setWaf(waf);
				}
			}	
			
			boolean hasNewDefectTracker = applicationService.validateApplicationDefectTracker(application, result);
			
			if (hasNewDefectTracker || (application.getDefectTracker() == null && application.getDefectList() != null))
				defectService.deleteByApplicationId(application.getId());
			
			Application databaseApplication = applicationService.loadApplication(application.getName().trim());
			if (databaseApplication != null && !databaseApplication.getId().equals(application.getId())) {
				result.rejectValue("name", "errors.nameTaken");
			}
			
			if (result.hasErrors())
				return "applications/form";
			
			applicationService.storeApplication(application);
			
			if (application.getProjectRoot() != null && !application.getProjectRoot().trim().equals("")) {
				Application app = applicationService.loadApplication(application.getId());
				
				scanMergeService.updateSurfaceLocation(app);
				scanMergeService.updateVulnerabilities(app);
				
				applicationService.storeApplication(app);
			}
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
			
			status.setComplete();
			return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/" + application.getId();
		}
	}
	
	private List<String> removeDuplicates(List<String> pathList) {
		List<String> distinctPath = new ArrayList<String>();
		for (int outerCounter = 0; outerCounter < pathList.size(); outerCounter++) {
			int innerCounter = 0;
			for (; innerCounter < outerCounter; innerCounter++) {
				if (pathList.get(outerCounter).equals(pathList.get(innerCounter))) {
					break;
				}
			}
			if (innerCounter == outerCounter)
				distinctPath.add(pathList.get(outerCounter));
		}
		Collections.sort(distinctPath);
		return distinctPath;
	}

	private PathTree getTreeStructure(List<String> pathList, PathTree pathTree, Application application) {
		for (String pathSegment : pathList) {
			if (pathSegment == null)
				continue;
			pathTree.addPath(pathSegment);
		}
		return pathTree;
	}
}
