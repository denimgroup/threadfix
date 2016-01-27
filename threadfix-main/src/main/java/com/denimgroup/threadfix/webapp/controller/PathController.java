////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.Node;
import com.denimgroup.threadfix.webapp.viewmodels.PathTree;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/path")
public class PathController {

    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private ScanMergeService scanMergeService;

	private final SanitizedLogger log = new SanitizedLogger(PathController.class);

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("projectRoot");
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView viewScan(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS,orgId,appId)) {
			return new ModelAndView("403");
		}
		
		ModelAndView mav = new ModelAndView("path/path");
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		List<String> pathList = list();
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
		PathTree pt = new PathTree(new Node("root"));
		pt = getTreeStructure(pathList, pt, application);
		mav.addObject(application);
		mav.addObject("pathTree", pt);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String getProjectRoot(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId, @ModelAttribute Application application,
			SessionStatus status) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		// TODO validate this attachment - not a high priority as it doesn't affect anything really
		app.setProjectRoot(application.getProjectRoot());
		applicationService.storeApplication(app, EventAction.APPLICATION_EDIT);
		scanMergeService.updateSurfaceLocation(app);
		scanMergeService.updateVulnerabilities(app, false);
		status.setComplete();
		return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/"
				+ String.valueOf(appId);
	}

	private List<String> removeDuplicates(List<String> pathList) {
		List<String> distinctPath = list();
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

	private PathTree getTreeStructure(List<String> pathList, PathTree pathTree, Application application) {
		for (String pathSegment : pathList) {
			if (pathSegment == null)
				continue;
			pathTree.addPath(pathSegment);
		}
		return pathTree;
	}
}
