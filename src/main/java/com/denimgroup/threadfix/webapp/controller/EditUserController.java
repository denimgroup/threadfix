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

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessControlMapService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;
import com.denimgroup.threadfix.webapp.viewmodels.AccessControlMapModel;

@Controller
@RequestMapping("/configuration/users/{userId}/edit")
@SessionAttributes("user")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class EditUserController {

	private UserService userService = null;
	private RoleService roleService = null;
	private AccessControlMapService accessControlMapService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@Autowired
	public EditUserController(AccessControlMapService accessControlMapService,
			RoleService roleService, UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
		this.accessControlMapService = accessControlMapService;
	}
	
	public EditUserController(){}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
				"passwordConfirm", "hasGlobalGroupAccess", "isLdapUser");
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processEdit(@PathVariable("userId") int userId, @ModelAttribute User user,
			BindingResult result, SessionStatus status, HttpServletRequest request, Model model) {
		
		User editedUser = userService.applyChanges(user, userId);
		
		new UserValidator(roleService).validate(editedUser, result);
		
		if (userService.hasRemovedAdminPermissions(editedUser) && !userService.canDelete(editedUser)) {
			result.rejectValue("hasGlobalGroupAccess", null, null, 
					"This would leave users unable to access the user management portion of ThreadFix.");
		}
		
		if (result.hasErrors()) {
			model.addAttribute("accessControlMapModel", getMapModel(userId));
			model.addAttribute("maps",accessControlMapService.loadAllMapsForUser(userId));
			model.addAttribute("contentPage", "config/users/editUserForm.jsp");
			return "ajaxFailureHarness";
		} else {

			User databaseUser = userService.loadUser(editedUser.getName());
			if (databaseUser != null && !databaseUser.getId().equals(editedUser.getId())) {
				result.rejectValue("name", "errors.nameTaken");
				model.addAttribute("accessControlMapModel", getMapModel(userId));
				model.addAttribute("maps",accessControlMapService.loadAllMapsForUser(userId));
				model.addAttribute("contentPage", "config/users/form.jsp");
				return "ajaxFailureHarness";
			}
			
			if (editedUser.getGlobalRole() != null && editedUser.getGlobalRole().getId() != null) {
				Role role = roleService.loadRole(editedUser.getGlobalRole().getId());
				if (role == null) {
					editedUser.setGlobalRole(null);
				}
			}
			
			String globalGroupAccess = request.getParameter("hasGlobalGroupAccess");
			
			Boolean hasGlobalGroup = globalGroupAccess != null && globalGroupAccess.equals("true");
			editedUser.setHasGlobalGroupAccess(hasGlobalGroup);
			userService.storeUser(editedUser);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			
			// For now, we'll say that if the name matches then they are the same.
			// This may not hold for AD scenarios.
			log.info("The User " + editedUser.getName() + " (id=" + editedUser.getId() + ") has been edited by user " + currentUser);

			model.addAttribute("contentPage", "/configuration/users");
			return "ajaxRedirectHarness";
		}
	}
	
	private AccessControlMapModel getMapModel(Integer userId) {
		AccessControlMapModel map = new AccessControlMapModel();
		map.setUserId(userId);
		return map;
	}

}
