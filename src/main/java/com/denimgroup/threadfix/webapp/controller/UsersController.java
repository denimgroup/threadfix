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

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.UserModel;

/**
 * @author dshannon
 * @author mcollins
 */
@Controller
@RequestMapping("/configuration/users")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class UsersController {

	private UserService userService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(UsersController.class);

	@Autowired
	public UsersController(UserService userService) {
		this.userService = userService;
	}
	
	public UsersController(){}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setDisallowedFields(new String[] { "id" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public String manageUsers(ModelMap model) {
		
		List<UserModel> userModels = new ArrayList<UserModel>();
		
		List<User> users = userService.loadAllUsers();
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		for (User user : users) {
			boolean deletable = userService.canDelete(user);
			boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
			
			UserModel userModel = new UserModel();
			userModel.setUser(user);
			userModel.setDeletable(deletable);
			userModel.setThisUser(isThisUser);
			userModels.add(userModel);
		}
		
		model.addAttribute("userModels", userModels);
		
		return "config/users/index";
	}

	@RequestMapping("/{userId}/delete")
	public String deleteUser(@PathVariable("userId") int userId, SessionStatus status) {
		User user = userService.loadUser(userId);
		
		if (user != null) {
			if (userService.canDelete(user)) {
				
				status.setComplete();
				
				String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
				
				boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
				
				userService.delete(user);
				
				if (isThisUser) {
					return "redirect:/j_spring_security_logout";
				} else {
					return "redirect:/configuration/users";
				}
			} else {
				return "redirect:/configuration/users/" + userId;
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
	}
}