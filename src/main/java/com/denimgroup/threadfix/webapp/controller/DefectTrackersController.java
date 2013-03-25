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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("/configuration/defecttrackers")
@SessionAttributes({"defectTracker","editDefectTracker"})
public class DefectTrackersController {
	
	DefectTrackersController(){}

	private DefectTrackerService defectTrackerService;
	private PermissionService permissionService;
	
	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);

	@Autowired
	public DefectTrackersController(PermissionService permissionService,
			DefectTrackerService defectTrackerService) {
		this.defectTrackerService = defectTrackerService;
		this.permissionService = permissionService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		addModelAttributes(model);
		return "config/defecttrackers/index";
	}
	
	private void addModelAttributes(Model model) {
		model.addAttribute(defectTrackerService.loadAllDefectTrackers());
		model.addAttribute("editDefectTracker", new DefectTracker());
		model.addAttribute("defectTracker", new DefectTracker());
		model.addAttribute("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());
		permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
	}

	@RequestMapping("/{defectTrackerId}")
	public ModelAndView detail(@PathVariable("defectTrackerId") int defectTrackerId) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		
		if (defectTracker == null) {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("config/defecttrackers/detail");
		mav.addObject(defectTracker);
		permissionService.addPermissions(mav, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
		return mav;
	}
	
	/**
	 * @param defectTrackerId
	 * @param status
	 * @return
	 */
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("/{defectTrackerId}/delete")
	public String deleteTracker(@PathVariable("defectTrackerId") int defectTrackerId,
			SessionStatus status, Model model) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		if (defectTracker != null) {
			defectTrackerService.deleteById(defectTrackerId);
			status.setComplete();
			addModelAttributes(model);
			model.addAttribute("contentPage", "config/defecttrackers/trackersTable.jsp");
			return "ajaxSuccessHarness";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
	}
}
