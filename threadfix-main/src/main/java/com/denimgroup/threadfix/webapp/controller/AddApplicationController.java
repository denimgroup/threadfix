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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/applications/new")
@SessionAttributes("application")
public class AddApplicationController {

	private OrganizationService organizationService = null;
	private PermissionService permissionService= null;
	private ApplicationService applicationService = null;
	private DefectTrackerService defectTrackerService = null;
	private WafService wafService = null;
	private ApplicationCriticalityService applicationCriticalityService = null;

	private final SanitizedLogger log = new SanitizedLogger(AddApplicationController.class);
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTracker.id", "uniqueId",
                "userName", "password", "waf.id", "projectName", "applicationCriticality.id");
	}
	
	@Autowired
	public AddApplicationController(OrganizationService organizationService,
			ApplicationService applicationService,
			DefectTrackerService defectTrackerService,
			WafService wafService,
			ApplicationCriticalityService applicationCriticalityService,
			PermissionService permissionService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.wafService = wafService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.permissionService = permissionService;
	}
	
	public AddApplicationController(){}

	@ModelAttribute
	public List<DefectTracker> populateDefectTrackers() {
		return defectTrackerService.loadAllDefectTrackers();
	}
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}

	@ModelAttribute
	public List<Waf> populateWafs() {
		return wafService.loadAll();
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String newSubmit(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application, BindingResult result,
			SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
			return "403";
		}
		
		if (application.getOrganization() == null) {
			Organization org = organizationService.loadOrganization(orgId);
			if (org != null) {
				application.setOrganization(org);
			}
		}
		
		applicationService.validateAfterCreate(application, result);
		
		if (result.hasErrors()) {
			permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS, 
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, null));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, null));
			
			return "applications/form";
		} else {

			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("User " + user + " has created an Application with the name " + application.getName() +
					", the ID " + application.getId() +
					", and the Organization " + application.getOrganization().getName());
			
			status.setComplete();
			return "redirect:/organizations/" + String.valueOf(orgId) + "/applications/" + application.getId();
		}
	}
}
