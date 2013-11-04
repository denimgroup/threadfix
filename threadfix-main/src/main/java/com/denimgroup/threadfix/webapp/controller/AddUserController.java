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

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.plugin.ldap.LdapServiceDelegateFactory;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;

@Controller
@RequestMapping("/configuration/users/new")
@SessionAttributes("user")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class AddUserController {

	private UserService userService = null;
	private RoleService roleService = null;
	private boolean ldapPluginInstalled = false;
	
	@Autowired
	private PermissionService permissionService;
	
	private final SanitizedLogger log = new SanitizedLogger(AddUserController.class);

	@Autowired
	public AddUserController(
			UserService userService, RoleService roleService) {
		this.roleService = roleService;
		this.userService = userService;
		ldapPluginInstalled = LdapServiceDelegateFactory.isEnterprise();
	}
	
	public AddUserController(){}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if(ldapPluginInstalled && permissionService.isEnterprise()){
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "hasGlobalGroupAccess", "isLdapUser");
		}else if(ldapPluginInstalled){
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "isLdapUser");
		}else if(permissionService.isEnterprise()){
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "hasGlobalGroupAccess");
		}else{
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "hasGlobalGroupAccess");
		}
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processNew(@Valid @ModelAttribute User user, BindingResult result, 
			SessionStatus status, Model model, HttpServletRequest request) {
		new UserValidator(roleService).validate(user, result);
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "config/users/newUserForm.jsp");
			return "ajaxFailureHarness";
		} else {
			User databaseUser = userService.loadUser(user.getName().trim());
			if (databaseUser != null) {
				result.rejectValue("name", "errors.nameTaken");
				model.addAttribute("contentPage", "config/users/newUserForm.jsp");
				return "ajaxFailureHarness";
			}

			userService.createUser(user);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a new User with the name " + user.getName() + 
					", the ID " + user.getId());
			status.setComplete();
			ControllerUtils.addSuccessMessage(request, 
					"User " + user.getName() + " has been created successfully.");
			model.addAttribute("contentPage", "/configuration/users");
			return "ajaxRedirectHarness";
		}
	}
}
