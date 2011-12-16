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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.Node;
import com.denimgroup.threadfix.webapp.viewmodels.PathTree;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/path")
public class PathController {

	private ApplicationService applicationService;
	private ScanMergeService scanMergeService;
	
	private final Log log = LogFactory.getLog(PathController.class);

	@Autowired
	public PathController(ApplicationService applicationService, ScanMergeService scanMergeService) {
		this.applicationService = applicationService;
		this.scanMergeService = scanMergeService;
	}

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String [] { "projectRoot" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView viewScan(@PathVariable("appId") int appId) {
		ModelAndView mav = new ModelAndView("path/path");
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		List<String> pathList = new ArrayList<String>();
		for (Vulnerability vuln : application.getVulnerabilities()) {
			if (vuln != null && vuln.getFindings() != null)
				for (Finding finding : vuln.getFindings()) {
					if (finding != null && finding.getSourceFileLocation() != null) {
						pathList.add(finding.getSourceFileLocation());
					}
				}
		}
		pathList = removeDuplicates(pathList);
		PathTree pt = new PathTree(new Node("root"));
		pt = getTreeStructure(pathList, pt);
		mav.addObject(application);
		mav.addObject("pathTree", pt);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String getProjectRoot(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId, @ModelAttribute Application application,
			SessionStatus status) {
		Application app = applicationService.loadApplication(appId);
		
		if (app == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		app.setProjectRoot(application.getProjectRoot());
		applicationService.storeApplication(app);
		scanMergeService.updateSurfaceLocation(app);
		scanMergeService.updateVulnerabilities(app);
		status.setComplete();
		return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/"
				+ String.valueOf(appId);
	}

	@RequestMapping(value = "/surface_structure")
	public ModelAndView getSurfaceStructure(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		boolean flag = false;
		if (application.getVulnerabilities() != null)
			for (Vulnerability vulnerability : application.getVulnerabilities())
				if (vulnerability != null && vulnerability.getSurfaceLocation() != null
						&& vulnerability.getSurfaceLocation().getPath() != null) {
					flag = true;
					break;
				}
		
		ModelAndView mav = new ModelAndView("path/surface_structure");
		mav.addObject(application);
		mav.addObject("sufficientInformation", flag);
		return mav;
	}

	@RequestMapping(value = "/code_structure")
	public ModelAndView getCodeStructure(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		Application application = applicationService.loadApplication(appId);
				
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		boolean flag = false;
		if (application.getFindingList() != null)
			for (Finding finding : application.getFindingList())
				if (finding != null && finding.getIsStatic()) {
					flag = true;
					break;
				}
		
		ModelAndView mav = new ModelAndView("path/code_structure");
		mav.addObject(application);
		mav.addObject("static", flag);
		return mav;
	}

	private List<String> removeDuplicates(List<String> pathList) {
		List<String> distinctPath = new ArrayList<String>();
		for (int i = 0; i < pathList.size(); i++) {
			int j = 0;
			for (; j < i; j++) {
				if (pathList.get(i).equals(pathList.get(j))) {
					break;
				}
			}
			if (j == i)
				distinctPath.add(pathList.get(i));
		}
		Collections.sort(distinctPath);
		return distinctPath;
	}

	private PathTree getTreeStructure(List<String> pathList, PathTree pt) {
		for (String s : pathList)
			pt.addPath(s);
		return pt;
	}
}
