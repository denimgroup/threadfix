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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/edit")
@SessionAttributes({"application", "scanParametersBean"})
public class EditApplicationController {
	
	public EditApplicationController(){}

	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);
	
	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private WafService wafService;
	private PermissionService permissionService;
	private ApplicationCriticalityService applicationCriticalityService = null;
	private OrganizationService organizationService;
	
	@Autowired
	public EditApplicationController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService, WafService wafService,
			PermissionService permissionService,
			ApplicationCriticalityService applicationCriticalityService,
			OrganizationService organizationService) {
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.wafService = wafService;
		this.permissionService = permissionService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.organizationService = organizationService;
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
	
	@ModelAttribute("teamList")
	public List<Organization> populateTeams() {
		return organizationService.loadAllActive();
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryFolder");
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model,
			HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return "403";
		}
		
		Application databaseApplication = applicationService.loadApplication(appId);
		if (databaseApplication == null || !databaseApplication.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		// These should not be editable in this method.
		// TODO split into 3 controllers and use setAllowedFields
		application.setWaf(databaseApplication.getWaf());
		application.setDefectTracker(databaseApplication.getDefectTracker());
		application.setUserName(databaseApplication.getUserName());
		application.setPassword(databaseApplication.getPassword());
		
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
			
			if (application.getWaf() != null && application.getWaf().getId() == null) {
				application.setWaf(null);
			}
			
			if (application.getDefectTracker() != null &&
					application.getDefectTracker().getId() == null) {
				application.setDefectTracker(null);
			}
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, appId));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, appId));
			
			model.addAttribute("contentPage", "applications/forms/editApplicationForm.jsp");
			return "ajaxFailureHarness";
		} else {
			application.setOrganization(organizationService.loadOrganization(application.getOrganization().getId()));
			applicationService.storeApplication(application);
//			applicationService.updateProjectRoot(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
			
			permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS,
					Permission.CAN_UPLOAD_SCANS,
					Permission.CAN_MODIFY_VULNERABILITIES,
					Permission.CAN_SUBMIT_DEFECTS,
					Permission.CAN_VIEW_JOB_STATUSES,
					Permission.CAN_GENERATE_REPORTS,
					Permission.CAN_MANAGE_DEFECT_TRACKERS,
					Permission.CAN_MANAGE_USERS);
			
			model.addAttribute("application", application);
			model.addAttribute("finding", new Finding());
			model.addAttribute("applicationTypes", FrameworkType.values());
			model.addAttribute("contentPage", "applications/detailHeader.jsp");
			ControllerUtils.addSuccessMessage(request,
					"The application was edited successfully.");
			
			return "ajaxSuccessHarness";
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
				
				if (application.getWaf() != null && application.getWaf().getId() != null && application.getWaf().getId() != 0) {
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
			model.addAttribute("addedWaf", true);
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
			applicationService.validateDefectTracker(application, result);
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
			
			permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS);
			
			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
			
			model.addAttribute("addedDefectTracker", true);
			model.addAttribute("contentPage", "applications/defectTrackerRow.jsp");
			return "ajaxSuccessHarness";
		}
	}
}
