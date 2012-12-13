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

import java.util.List;

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

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;

@Controller
@RequestMapping("/configuration/users/new")
@SessionAttributes("user")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class AddUserController {

	private DefaultConfigService defaultConfigService = null;
	private UserService userService = null;
	private RoleService roleService = null;
	private OrganizationService organizationService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddApplicationChannelController.class);

	@Autowired
	public AddUserController(OrganizationService organizationService, 
			UserService userService, RoleService roleService, 
			DefaultConfigService defaultConfigService) {
		this.organizationService = organizationService;
		this.defaultConfigService = defaultConfigService;
		this.roleService = roleService;
		this.userService = userService;
	}
	
	public AddUserController(){}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
				"passwordConfirm", "hasGlobalGroupAccess", "isLdapUser");
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model) {
		User user = new User();
		
		DefaultConfiguration defaultsModel = defaultConfigService.loadCurrentConfiguration();
		
		if (defaultsModel != null) {
			user.setHasGlobalGroupAccess(defaultsModel.getGlobalGroupEnabled());
			if (user.getHasGlobalGroupAccess()) {
				user.setGlobalRole(roleService.loadRole(defaultsModel.getDefaultRoleId()));
			}
		}
		
		model.addAttribute("defaults", defaultConfigService.loadCurrentConfiguration());
		
		// Should probably switch to filter after we figure this out
		model.addAttribute("teams",organizationService.loadAllActive());
		model.addAttribute(user);
		return "config/users/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processNew(@Valid @ModelAttribute User user, BindingResult result, SessionStatus status) {
		new UserValidator().validate(user, result);
		if (result.hasErrors()) {
			return "config/users/form";
		} else {
			User databaseUser = userService.loadUser(user.getName().trim());
			if (databaseUser != null) {
				result.rejectValue("name", "errors.nameTaken");
				return "config/users/form";
			}

			userService.createUser(user);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a new User with the name " + user.getName() + 
					", the ID " + user.getId());
			status.setComplete();
			return "redirect:/configuration/users/" + user.getId() + "/edit";
		}
	}
}
