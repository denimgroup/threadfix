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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/modalEdit")
@SessionAttributes("organization")
public class EditOrganizationController {
	
	public EditOrganizationController(){}

	private OrganizationService organizationService = null;
	private PermissionService permissionService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditOrganizationController.class);

	@Autowired
	public EditOrganizationController(PermissionService permissionService,
			OrganizationService organizationService) {
		this.organizationService = organizationService;
		this.permissionService = permissionService;
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name");
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@RequestMapping(method = RequestMethod.POST)
	public String editSubmit(@PathVariable("orgId") int orgId, Model model,
			@Valid @ModelAttribute Organization organization, BindingResult result,
			SessionStatus status, HttpServletRequest request) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_TEAMS, orgId, null) ||
				!organization.isActive()) {
			return "403";
		}
		
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "organizations/editTeamForm.jsp");
			Organization dbOrg = organizationService.loadOrganization(orgId);
			model.addAttribute("originalName", dbOrg.getName());
			return "ajaxFailureHarness";
		} else {
			
			if (organization.getName() != null && organization.getName().trim().isEmpty()) {
				result.rejectValue("name", null, null, "This field cannot be blank");
				model.addAttribute("contentPage", "organizations/editTeamForm.jsp");
				organization.setName(null);
				Organization dbOrg = organizationService.loadOrganization(orgId);
				model.addAttribute("originalName", dbOrg.getName());
				return "ajaxFailureHarness";
			}
			
			Organization databaseOrganization = organizationService.loadOrganization(organization.getName().trim());
			if (databaseOrganization != null && !databaseOrganization.getId().equals(organization.getId())) {
				result.rejectValue("name", "errors.nameTaken");
				model.addAttribute("contentPage", "organizations/editTeamForm.jsp");
				Organization dbOrg = organizationService.loadOrganization(orgId);
				model.addAttribute("originalName", dbOrg.getName());
				return "ajaxFailureHarness";
			}
			
			organizationService.storeOrganization(organization);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("The Organization " + organization.getName() + " (id=" + organization.getId() + ") has been edited by user " + user);
			
			ControllerUtils.addSuccessMessage(request, 
					"Team " + organization.getName() + " has been edited successfully.");
			
			model.addAttribute("contentPage", "/organizations/" + String.valueOf(orgId));
			return "ajaxRedirectHarness";
		}
	}

}
