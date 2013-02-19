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
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessControlMapService;
import com.denimgroup.threadfix.service.OrganizationService;
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
	private OrganizationService organizationService = null;
	private AccessControlMapService accessControlMapService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@Autowired
	public EditUserController(OrganizationService organizationService ,
			AccessControlMapService accessControlMapService,
			RoleService roleService, UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
		this.accessControlMapService = accessControlMapService;
		this.organizationService = organizationService;
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

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView editForm(@PathVariable("userId") int userId, Model model) {
		User user = userService.loadUser(userId);
		
		if (user == null){
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		boolean isThisUser = currentUser != null && user.getName().equals(currentUser);
		
		ModelAndView mav = new ModelAndView("config/users/form");
		mav.addObject(user);
		mav.addObject("teams",organizationService.loadAllActive());
		mav.addObject("maps",accessControlMapService.loadAllMapsForUser(userId));
		mav.addObject("accessControlMapModel", getMapModel(userId));
		mav.addObject("isThisUser", isThisUser);
		return mav;
	}
	
	private AccessControlMapModel getMapModel(Integer userId) {
		AccessControlMapModel map = new AccessControlMapModel();
		map.setUserId(userId);
		return map;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processEdit(@PathVariable("userId") int userId, @ModelAttribute User user,
			BindingResult result, SessionStatus status, HttpServletRequest request, Model model) {
		new UserValidator(roleService).validate(user, result);
		
		if (userService.hasRemovedAdminPermissions(user) && !userService.canDelete(user)) {
			result.rejectValue("hasGlobalGroupAccess", null, null, 
					"This would leave users unable to access the user management portion of ThreadFix.");
		}
		
		if (result.hasErrors()) {
			model.addAttribute("accessControlMapModel", getMapModel(userId));
			model.addAttribute("maps",accessControlMapService.loadAllMapsForUser(userId));
			return "config/users/form";
		} else {

			User databaseUser = userService.loadUser(user.getName());
			if (databaseUser != null && !databaseUser.getId().equals(user.getId())) {
				result.rejectValue("name", "errors.nameTaken");
				model.addAttribute("accessControlMapModel", getMapModel(userId));
				model.addAttribute("maps",accessControlMapService.loadAllMapsForUser(userId));
				return "config/users/form";
			}
			
			if (user.getGlobalRole() != null && user.getGlobalRole().getId() != null) {
				Role role = roleService.loadRole(user.getGlobalRole().getId());
				if (role == null) {
					user.setGlobalRole(null);
				}
			}
			
			String globalGroupAccess = request.getParameter("hasGlobalGroupAccess");
			
			Boolean hasGlobalGroup = globalGroupAccess != null && globalGroupAccess.equals("true");
			user.setHasGlobalGroupAccess(hasGlobalGroup);
			userService.storeUser(user);
			
			status.setComplete();
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			
			// For now, we'll say that if the name matches then they are the same.
			// This may not hold for AD scenarios.
			log.info("The User " + user.getName() + " (id=" + user.getId() + ") has been edited by user " + currentUser);

			return "redirect:/configuration/users";
		}
	}

}
