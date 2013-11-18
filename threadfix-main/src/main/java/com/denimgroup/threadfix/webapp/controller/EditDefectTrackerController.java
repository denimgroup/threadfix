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

import java.util.List;

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/defecttrackers/{defectTrackerId}/edit")
@SessionAttributes({"defectTracker", "editDefectTracker"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class EditDefectTrackerController {
	
	public EditDefectTrackerController(){}

	private DefectTrackerService defectTrackerService;
	private DefectService defectService;
	private PermissionService permissionService;
	
	private final Log log = LogFactory.getLog(DefectTrackersController.class);

	@Autowired
	public EditDefectTrackerController(DefectTrackerService defectTrackerService,
			PermissionService permissionService,
			DefectService defectService) {
		this.defectTrackerService = defectTrackerService;
		this.defectService = defectService;
		this.permissionService = permissionService;
	}

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTrackerType.id");
	}

	@ModelAttribute
	public List<DefectTrackerType> populateDefectTrackerTypes() {
		return defectTrackerService.loadAllDefectTrackerTypes();
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView editForm(@PathVariable("defectTrackerId") int defectTrackerId) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		
		if (defectTracker == null) {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("config/defecttrackers/form");
		mav.addObject(defectTracker);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(@PathVariable("defectTrackerId") int defectTrackerId,
			@Valid @ModelAttribute DefectTracker defectTracker, BindingResult result,
			SessionStatus status, Model model) {
		
		DefectTracker databaseDefectTracker;
		
		if (defectTracker == null || defectTracker.getName() == null || 
				defectTracker.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		} else {
			databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTracker.getName().trim());
			if (databaseDefectTracker != null && !databaseDefectTracker.getId().equals(defectTracker.getId())) {
				result.rejectValue("name", "errors.nameTaken");
			} else if (!defectTrackerService.checkUrl(defectTracker, result)) {
				if (!result.hasFieldErrors("url")) {
					result.rejectValue("url", "errors.invalid", new String [] { "URL" }, null);		
				} else if (result.getFieldError("url").getDefaultMessage() != null &&
						result.getFieldError("url").getDefaultMessage().equals(
								AbstractDefectTracker.INVALID_CERTIFICATE)){
					model.addAttribute("showKeytoolLink", true);
				}
			}
		}

		if (result.hasErrors()) {
			return "config/defecttrackers/form";
		} else {	
			databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
			if (databaseDefectTracker != null && databaseDefectTracker.getDefectTrackerType() != null &&
					defectTracker != null && defectTracker.getDefectTrackerType() != null &&
					defectTracker.getDefectTrackerType().getId() != null &&
					!defectTracker.getDefectTrackerType().getId().equals(
							databaseDefectTracker.getDefectTrackerType().getId())) {
				defectService.deleteByDefectTrackerId(defectTrackerId);
			}
						
			defectTrackerService.storeDefectTracker(defectTracker);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			if (defectTracker != null) {
				log.debug("The DefectTracker " + defectTracker.getName() + " (id=" + defectTracker.getId() + ") has been edited by user " + user);
			}
			
			status.setComplete();
			return "redirect:/configuration/defecttrackers/" + defectTrackerId;
		}
	}
	
	@RequestMapping(value="/ajax", method = RequestMethod.POST)
	public String processSubmitAjax(@PathVariable("defectTrackerId") int defectTrackerId,
			@Valid @ModelAttribute DefectTracker defectTracker, BindingResult result,
			SessionStatus status, Model model) {
		
		if (defectTracker != null) {
			defectTracker.setId(defectTrackerId);
		}
		
		DefectTracker databaseDefectTracker;
		
		if (defectTracker == null || defectTracker.getName() == null || 
				defectTracker.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		} else {
			databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTracker.getName().trim());
			if (databaseDefectTracker != null && !databaseDefectTracker.getId().equals(defectTracker.getId())) {
				result.rejectValue("name", "errors.nameTaken");
			} else if (!defectTrackerService.checkUrl(defectTracker, result)) {
				if (!result.hasFieldErrors("url")) {
					result.rejectValue("url", "errors.invalid", new String [] { "URL" }, null);		
				} else if (result.getFieldError("url").getDefaultMessage() != null &&
						result.getFieldError("url").getDefaultMessage().equals(
								AbstractDefectTracker.INVALID_CERTIFICATE)){
					model.addAttribute("showKeytoolLink", true);
				}
			}
		}
		
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "config/defecttrackers/forms/editDTForm.jsp");
			return "ajaxFailureHarness";
		} else {
			databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
			if (databaseDefectTracker != null && databaseDefectTracker.getDefectTrackerType() != null &&
					defectTracker != null && defectTracker.getDefectTrackerType() != null &&
					defectTracker.getDefectTrackerType().getId() != null &&
					!defectTracker.getDefectTrackerType().getId().equals(
							databaseDefectTracker.getDefectTrackerType().getId())) {
				defectService.deleteByDefectTrackerId(defectTrackerId);
			}
			
			defectTrackerService.storeDefectTracker(defectTracker);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			if (defectTracker != null) {
				log.debug("The DefectTracker " + defectTracker.getName() + " (id=" + defectTracker.getId() + ") has been edited by user " + user);
				model.addAttribute("successMessage", 
						"Defect Tracker " + defectTracker.getName() + " has been edited successfully.");
			}
			
			model.addAttribute(defectTrackerService.loadAllDefectTrackers());
			model.addAttribute("defectTracker", new DefectTracker());
			model.addAttribute("editDefectTracker", new DefectTracker());
			model.addAttribute("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());

			permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
			model.addAttribute("contentPage", "config/defecttrackers/trackersTable.jsp");
			return "ajaxSuccessHarness";
		}
	}
}
