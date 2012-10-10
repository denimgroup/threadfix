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
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;

@Controller
@RequestMapping("/configuration/users/new")
@SessionAttributes("user")
public class AddUserController {

	private UserService userService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddApplicationChannelController.class);

	@Autowired
	public AddUserController(UserService userService) {
		this.userService = userService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String [] { "name", "role.id", "unencryptedPassword", "passwordConfirm" });
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return userService.loadAllRoles();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model) {
		User user = new User();
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
			
			if (user.getRole() == null || user.getRole().getId() == null 
					|| userService.loadRole(user.getRole().getId()) == null) {
				result.rejectValue("role.id", "errors.invalid", new String [] { "Role Choice" }, null);
				return "config/users/form";
			}
			
			userService.createUser(user);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a new User with the name " + user.getName() + 
					", the ID " + user.getId() +
					", and the role " + user.getRole().getDisplayName());
			status.setComplete();
			return "redirect:/configuration/users/" + user.getId() + "/groups";
		}
	}
	
}
