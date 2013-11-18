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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.plugin.ldap.LdapServiceDelegateFactory;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.AccessControlMapModel;

/**
 * @author dshannon
 * @author mcollins
 */
@Controller
@SessionAttributes("user")
@RequestMapping("/configuration/users")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class UsersController {

	private UserService userService = null;
	private RoleService roleService = null;
	private DefaultConfigService defaultConfigService = null;
	private final SanitizedLogger log = new SanitizedLogger(UsersController.class);

	@Autowired
	public UsersController(RoleService roleService, 
			DefaultConfigService defaultConfigurationService,
			UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
		this.defaultConfigService = defaultConfigurationService;
	}
	
	public UsersController(){}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setDisallowedFields("id");
	}
	
	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(ModelMap model, HttpServletRequest request) {
		
		List<User> users = userService.loadAllUsers();
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		for (User user : users) {
			user.setIsDeletable(userService.canDelete(user));
			user.setIsThisUser(currentUser != null && currentUser.equals(user.getName()));
		}
		model.addAttribute("ldap_plugin",LdapServiceDelegateFactory.isEnterprise());
		model.addAttribute("users", users);
		
		User user = new User();
		
		DefaultConfiguration defaultsModel = defaultConfigService.loadCurrentConfiguration();
		
		if (defaultsModel != null) {
			user.setHasGlobalGroupAccess(defaultsModel.getGlobalGroupEnabled());
			if (user.getHasGlobalGroupAccess()) {
				user.setGlobalRole(roleService.loadRole(defaultsModel.getDefaultRoleId()));
			}
		}
		
		model.addAttribute("user", user);
		model.addAttribute("accessControlMapModel", new AccessControlMapModel());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));
		
		return "config/users/index";
	}

	@RequestMapping("/{userId}/delete")
	public String deleteUser(@PathVariable("userId") int userId, 
			HttpServletRequest request, SessionStatus status) {
		User user = userService.loadUser(userId);
		
		if (user != null) {
			String userName = user.getName();
			
			if (userService.canDelete(user)) {
				
				status.setComplete();
				
				String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
				
				boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
				
				userService.delete(user);
				
				if (isThisUser) {
					return "redirect:/j_spring_security_logout";
				} else {
					ControllerUtils.addSuccessMessage(request, "User " + userName + " was deleted successfully.");
					return "redirect:/configuration/users";
				}
			} else {
				ControllerUtils.addErrorMessage(request, "User " + userName + " cannot be deleted.");
				return "redirect:/configuration/users";
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
	}
}