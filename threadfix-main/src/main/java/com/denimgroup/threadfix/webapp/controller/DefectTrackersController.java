////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.service.ScheduledDefectTrackerUpdateService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/configuration/defecttrackers")
@SessionAttributes({"defectTracker","editDefectTracker"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class DefectTrackersController {
	
    @Autowired
	private DefectTrackerService defectTrackerService;

    @Autowired
    private ScheduledDefectTrackerUpdateService scheduledDefectTrackerUpdateService;

	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
        model.addAttribute(new DefectTracker());
        PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
        return "config/defecttrackers/index";
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
        PermissionUtils.addPermissions(mav, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
		return mav;
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("/{defectTrackerId}/delete")
	public @ResponseBody RestResponse<String> deleteTracker(@PathVariable("defectTrackerId") int defectTrackerId,
			SessionStatus status, Model model) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		if (defectTracker != null) {
			defectTrackerService.deleteById(defectTrackerId);
			return RestResponse.success("Defect Tracker was successfully deleted.");
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("/info")
	@JsonView(AllViews.DefectTrackerInfos.class)
	public @ResponseBody RestResponse<Map<String, Object>> getList() {
		Map<String, Object> map = new HashMap<>();
        map.put("defectTrackerTypes", defectTrackerService.loadAllDefectTrackerTypes());
        map.put("defectTrackers", defectTrackerService.loadAllDefectTrackers());
        map.put("scheduledUpdates", scheduledDefectTrackerUpdateService.loadAll());
        return RestResponse.success(map);
	}
}
