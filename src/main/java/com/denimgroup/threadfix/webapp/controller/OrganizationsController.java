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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.viewmodels.QuickStartModel;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@SessionAttributes(value = {"organization", "application"})
@RequestMapping("/organizations")
public class OrganizationsController {
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}
	
	public OrganizationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

	private OrganizationService organizationService = null;
	private ApplicationService applicationService = null;
	private ApplicationCriticalityService applicationCriticalityService = null;
	private PermissionService permissionService = null;
	private ChannelTypeService channelTypeService = null;
	
	@Autowired
	public OrganizationsController(OrganizationService organizationService,
			ChannelTypeService channelTypeService, PermissionService permissionService, 
			ApplicationService applicationService, 
			ApplicationCriticalityService applicationCriticalityService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.permissionService = permissionService;
		this.channelTypeService = channelTypeService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		addModelObjects(model);
		model.addAttribute("quickStartModel", new QuickStartModel());
		return "organizations/index";
	}
	
	private void addModelObjects(Model model) {
		List<Organization> organizations = organizationService.loadAllActiveFilter();

		// for quick start
		model.addAttribute("channels", channelTypeService.getChannelTypeOptions(null));
		
		applicationService.generateVulnerabilityReports(organizations);
		model.addAttribute(organizations);
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
		
		Object test = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (test instanceof ThreadFixUserDetails) {
			model.addAttribute("shouldChangePassword",
					!((ThreadFixUserDetails) test).hasChangedInitialPassword());
		}
	}

	@RequestMapping("/{orgId}")
	public ModelAndView detail(@PathVariable("orgId") int orgId) {
		Organization organization = organizationService.loadOrganization(orgId);
		List<Application> apps = permissionService.filterApps(organization);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,null) && 
				(apps == null || apps.size() == 0)) {
			
			return new ModelAndView("403");
			
		} else {
			ModelAndView mav = new ModelAndView("organizations/detail");
			permissionService.addPermissions(mav, orgId, null, 
					Permission.CAN_MANAGE_APPLICATIONS, Permission.CAN_MANAGE_TEAMS);
			applicationService.generateVulnerabilityReports(organization);
			mav.addObject("apps", apps);
			mav.addObject(organization);
			return mav;
		}
	}
	
	@RequestMapping("/teamTable")
	public String teamTable(Model model) {
		addModelObjects(model);
		model.addAttribute("contentPage", "organizations/indexTeamTable.jsp");
		return "ajaxSuccessHarness";
	}
	
	@RequestMapping(value="/modalAdd", method = RequestMethod.POST)
	public String newSubmit2(@Valid @ModelAttribute Organization organization, BindingResult result,
			SessionStatus status, Model model) {
		model.addAttribute("contentPage", "organizations/newTeamForm.jsp");
		if (result.hasErrors()) {
			return "ajaxFailureHarness";
		} else {
			
			if (organization.getName() != null && organization.getName().trim().isEmpty()) {
				result.rejectValue("name", null, null, "This field cannot be blank");
				return "ajaxFailureHarness";
			}
			
			Organization databaseOrganization = organizationService.loadOrganization(organization.getName().trim());
			if (databaseOrganization != null) {
				result.rejectValue("name", "errors.nameTaken");
				return "ajaxFailureHarness";
			}
			
			organizationService.storeOrganization(organization);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(user + " has created a new Organization with the name " + organization.getName() + 
					" and ID " + organization.getId());
			status.setComplete();
			return "redirect:/organizations/teamTable";
		}
	}

	@RequestMapping("/{orgId}/delete")
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TEAMS')")
	public String deleteOrg(@PathVariable("orgId") int orgId, SessionStatus status) {
		Organization org = organizationService.loadOrganization(orgId);
		if (org == null || !org.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,null)){
			return "403";
			
		} else {
			organizationService.deactivateOrganization(org);
			status.setComplete();
			log.info("Organization soft deletion was successful on Organization " + org.getName() + ".");
			return "redirect:/organizations";
		}
	}
	
	@RequestMapping(value="/{orgId}/modalAddApp", method = RequestMethod.POST)
	public String submitApp(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application, BindingResult result,
			SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
			return "403";
		}
		Organization org = null;
		if (application.getOrganization() == null) {
			org = organizationService.loadOrganization(orgId);
			if (org != null) {
				application.setOrganization(org);
			}
		} else {
			org = application.getOrganization();
		}
		
		applicationService.validateAfterCreate(application, result);
		
		if (result.hasErrors()) {
			permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS, 
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("org",org);
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, null));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, null));
			
			model.addAttribute("contentPage", "applications/forms/newApplicationForm.jsp");
			
			return "ajaxFailureHarness";
		} else {

			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("User " + user + " has created an Application with the name " + application.getName() +
					", the ID " + application.getId() +
					", and the Organization " + application.getOrganization().getName());
			
			status.setComplete();
			return "redirect:/organizations/teamTable";
		}
	}
}
