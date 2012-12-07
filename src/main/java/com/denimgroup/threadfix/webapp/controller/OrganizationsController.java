////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@RequestMapping("/organizations")
public class OrganizationsController {
	
	public OrganizationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

	private OrganizationService organizationService = null;
	private PermissionService permissionService = null;
	private ApplicationService applicationService = null;
	
	@Autowired
	public OrganizationsController(OrganizationService organizationService,
			PermissionService permissionService, ApplicationService applicationService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.permissionService = permissionService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		List<Organization> organizations = organizationService.loadAllActiveFilter();
		applicationService.generateVulnerabilityReports(organizations);
		model.addAttribute(organizations);
		
		Object test = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (test instanceof ThreadFixUserDetails) {
			model.addAttribute("shouldChangePassword",
					!((ThreadFixUserDetails) test).hasChangedInitialPassword());
		}
		
		return "organizations/index";
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
}
