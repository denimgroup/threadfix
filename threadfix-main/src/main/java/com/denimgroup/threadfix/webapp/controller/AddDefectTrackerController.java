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

import javax.servlet.http.HttpServletRequest;
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/defecttrackers/new")
@SessionAttributes("defectTracker")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class AddDefectTrackerController {

	private DefectTrackerService defectTrackerService;
	private ApplicationService applicationService;
	private PermissionService permissionService;
	
	public AddDefectTrackerController(){}
	
	private final Log log = LogFactory.getLog(AddDefectTrackerController.class);

	@Autowired
	public AddDefectTrackerController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService, PermissionService permissionService) {
		this.defectTrackerService = defectTrackerService;
		this.applicationService = applicationService;
		this.permissionService = permissionService;
	
	}

	@InitBinder
	public void initBinder(WebDataBinder binder) {
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
	public String setup(Model model) {
		DefectTracker defectTracker = new DefectTracker();
		model.addAttribute(defectTracker);
		return "config/defecttrackers/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(@Valid @ModelAttribute DefectTracker defectTracker,
			BindingResult result, SessionStatus status, Model model,
			HttpServletRequest request) {
		if (defectTracker.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "config/defecttrackers/forms/createDTForm.jsp");
			return "ajaxFailureHarness";
		} else {
			
			DefectTracker databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTracker.getName().trim());
			if (databaseDefectTracker != null)
				result.rejectValue("name", "errors.nameTaken");

			if (defectTracker.getDefectTrackerType() == null) {
				result.rejectValue("defectTrackerType.id", "errors.invalid", 
						new String [] { "Defect Tracker Type" }, null );
			
			} else if (defectTrackerService.loadDefectTrackerType(defectTracker.getDefectTrackerType().getId()) == null) {
				result.rejectValue("defectTrackerType.id", "errors.invalid", 
						new String [] { defectTracker.getDefectTrackerType().getId().toString() }, null );
			} else if (!defectTrackerService.checkUrl(defectTracker, result)) {
				if (!result.hasFieldErrors("url")) {
					result.rejectValue("url", "errors.invalid", new String [] { "URL" }, null);		
				} else if (result.getFieldError("url").getDefaultMessage() != null &&
						result.getFieldError("url").getDefaultMessage().equals(
								AbstractDefectTracker.INVALID_CERTIFICATE)){
					model.addAttribute("showKeytoolLink", true);
				}
			}
			
			if (result.hasErrors()) {
				model.addAttribute("contentPage", "config/defecttrackers/forms/createDTForm.jsp");
				return "ajaxFailureHarness";
			}
			
			defectTrackerService.storeDefectTracker(defectTracker);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(user + " has successfully created a Defect Tracker with the name " + defectTracker.getName() +
					", the URL " + defectTracker.getUrl() + 
					", the type " + defectTracker.getDefectTrackerType().getName() + 
					", and the ID " + defectTracker.getId());
			
			String referrer = request.getHeader("referer");
			if (referrer.contains("configuration/defecttrackers")) {
				model.addAttribute("contentPage", "/configuration/defecttrackers");
				ControllerUtils.addSuccessMessage(request, 
						"Defect Tracker " + defectTracker.getName() + " has been created successfully.");
				return "ajaxRedirectHarness";
			} else {
			
				Application application = null;
				if (request.getParameter("applicationId") != null) {
					Integer testId = null;
					try {
						testId = Integer.valueOf((String)request.getParameter("applicationId"));
						application = applicationService.loadApplication(testId);
					} catch (NumberFormatException e) {
						log.warn("Non-numeric value discovered in applicationId field. Someone is trying to tamper with it.");
					}
				}
				
				model.addAttribute("application", application);
				model.addAttribute("contentPage", "applications/forms/addDTForm.jsp");
				
				model.addAttribute("newDefectTracker", defectTracker);
				model.addAttribute("defectTrackerList", defectTrackerService.loadAllDefectTrackers());
				model.addAttribute("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());
				model.addAttribute("defectTracker", new DefectTracker());
				permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
				return "ajaxSuccessHarness";
			}
		}
	}
}
