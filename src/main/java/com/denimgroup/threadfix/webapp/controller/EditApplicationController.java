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

import org.springframework.beans.factory.annotation.Autowired;
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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/edit")
@SessionAttributes("application")
public class EditApplicationController {
	
	public EditApplicationController(){}

	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);
	
	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private WafService wafService;
	private PermissionService permissionService;
	private ApplicationCriticalityService applicationCriticalityService = null;
	
	@Autowired
	public EditApplicationController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService, WafService wafService,
			PermissionService permissionService,
			ApplicationCriticalityService applicationCriticalityService) {
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.wafService = wafService;
		this.permissionService = permissionService;
		this.applicationCriticalityService = applicationCriticalityService;
	}

	@ModelAttribute("defectTrackerList")
	public List<DefectTracker> populateDefectTrackers() {
		return defectTrackerService.loadAllDefectTrackers();
	}

	@ModelAttribute("wafList")
	public List<Waf> populateWafs() {
		return wafService.loadAll();
	}
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "name", "url", "defectTracker.id", "userName", 
				"password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView setupForm(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return new ModelAndView("403");
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		applicationService.decryptCredentials(application);
		
		if (application.getPassword() != null && !"".equals(application.getPassword())) {
			application.setPassword(Application.TEMP_PASSWORD);
		}

		ModelAndView mav = new ModelAndView("applications/form");
		
		permissionService.addPermissions(mav, orgId, appId, Permission.CAN_MANAGE_DEFECT_TRACKERS, 
				Permission.CAN_MANAGE_WAFS);
		
		mav.addObject("canSetDefectTracker", permissionService.isAuthorized(
				Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, appId));
		
		mav.addObject("canSetWaf", permissionService.isAuthorized(
				Permission.CAN_MANAGE_WAFS, orgId, appId));

		mav.addObject(application);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		if(!result.hasErrors()) {
			applicationService.validateAfterEdit(application, result);
		}
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
			permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_DEFECT_TRACKERS, 
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, appId));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, appId));
			
			return "applications/form";
		} else {
			applicationService.storeApplication(application);
			applicationService.updateProjectRoot(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
			
			status.setComplete();
			return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/" + application.getId();
		}
	}
	
	@RequestMapping(value="/wafAjax", method = RequestMethod.POST)
	public String processSubmitAjaxWaf(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		if(application != null && application.getId() != null) {
			Application databaseApplication = applicationService.loadApplication(application.getId());
			if (databaseApplication == null) {
				result.rejectValue("waf.id", null, null, "We were unable to retrieve the application.");
			} else {
				if (application.getWaf() != null && (application.getWaf().getId() == null ||
						application.getWaf().getId() == 0)) {
					databaseApplication.setWaf(null);
				}
				
				if (application.getWaf() != null && application.getWaf().getId() != null) {
					Waf waf = wafService.loadWaf(application.getWaf().getId());
					
					if (waf == null) {
						result.rejectValue("waf.id", "errors.invalid", 
								new String [] { "WAF Choice" }, null);
					} else {
						databaseApplication.setWaf(waf);
					}
				}
				
				applicationService.storeApplication(databaseApplication);
				
				String user = SecurityContextHolder.getContext().getAuthentication().getName();
				
				log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
				
				model.addAttribute("application", databaseApplication);
			}
		} else {
			result.rejectValue("waf.id", null, null, "We were unable to retrieve the application.");
		}
		
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "applications/forms/addWafForm.jsp");
			return "ajaxFailureHarness";
		} else {
			model.addAttribute("contentPage", "applications/wafRow.jsp");
			return "ajaxSuccessHarness";
		}
	}
	
	@RequestMapping(value="/addDTAjax", method = RequestMethod.POST)
	public String processSubmitAjaxDefectTracker(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		if(!result.hasErrors()) {
			applicationService.validateAfterEdit(application, result);
		}
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
			permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_DEFECT_TRACKERS, 
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, appId));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, appId));
			
			model.addAttribute("contentPage", "applications/forms/addDTForm.jsp");
			return "ajaxFailureHarness";
			
		} else {
			applicationService.storeApplication(application);
			applicationService.updateProjectRoot(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
			
			status.setComplete();
			
			model.addAttribute("contentPage", "applications/defectTrackerRow.jsp");
			return "ajaxSuccessHarness";
		}
	}
}
