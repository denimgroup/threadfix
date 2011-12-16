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
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.service.DefectTrackerService;

@Controller
@RequestMapping("/configuration/defecttrackers")
public class DefectTrackersController {

	private DefectTrackerService defectTrackerService;
	
	private final Log log = LogFactory.getLog(DefectTrackersController.class);

	@Autowired
	public DefectTrackersController(DefectTrackerService defectTrackerService) {
		this.defectTrackerService = defectTrackerService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute(defectTrackerService.loadAllDefectTrackers());
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
		return mav;
	}
	
	@RequestMapping("/{defectTrackerId}/delete")
	public String deleteOrg(@PathVariable("defectTrackerId") int defectTrackerId,
			SessionStatus status) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		if (defectTracker != null) {
			defectTrackerService.deleteById(defectTrackerId);
			status.setComplete();
			return "redirect:/configuration/defecttrackers";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
	}
}
