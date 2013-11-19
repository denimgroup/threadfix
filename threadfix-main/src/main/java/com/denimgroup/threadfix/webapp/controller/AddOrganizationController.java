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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/modalAdd")
@SessionAttributes("organization")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TEAMS')")
public class AddOrganizationController {

	private OrganizationService organizationService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddOrganizationController.class);

	@Autowired
	public AddOrganizationController(OrganizationService organizationService) {
		this.organizationService = organizationService;
	}
	
	public AddOrganizationController(){}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name");
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String newSubmit2(@Valid @ModelAttribute Organization organization, BindingResult result,
			SessionStatus status, Model model, HttpServletRequest request) {
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
			
			ControllerUtils.addSuccessMessage(request, 
					"Team " + organization.getName() + " has been created successfully.");
			
			status.setComplete();
			return "redirect:/organizations/teamTable";
		}
	}
}
