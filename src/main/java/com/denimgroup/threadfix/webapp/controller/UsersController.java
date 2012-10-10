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

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessGroupService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.UserModel;

/**
 * @author dshannon
 * 
 */
@Controller
@RequestMapping("/configuration/users")
public class UsersController {

	private UserService userService = null;
	private AccessGroupService groupService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(UsersController.class);

	@Autowired
	public UsersController(UserService userService,
			AccessGroupService groupService) {
		this.userService = userService;
		this.groupService = groupService;
	}

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
			boolean lastAdmin = userService.isAdmin(user) && 1 == userService.countActiveAdmins();
			boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
			
			UserModel userModel = new UserModel();
			userModel.setUser(user);
			userModel.setLastAdmin(lastAdmin);
			userModel.setThisUser(isThisUser);
			userModels.add(userModel);
		}
		
		model.addAttribute("userModels", userModels);
		
		return "config/users/index";
	}

	@RequestMapping("/{userId}")
	public ModelAndView detail(@PathVariable("userId") int userId) {
		User user = userService.loadUser(userId);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
		
		if (user == null) {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
		
		StringBuilder builder = new StringBuilder();
		String groupString = null;
		List<AccessGroup> groups = groupService.getGroupsForUser(userId);
		
		if (groups != null && groups.size() > 0) {
			for (AccessGroup group : groups) {
				builder.append(group.getName());
				builder.append(", ");
			}
			
			if (builder.length() > 2) {
				groupString = builder.substring(0, builder.length() - 2);
			}
		}
		
		boolean lastAdmin = userService.isAdmin(user) && 1 == userService.countActiveAdmins();
		
		ModelAndView mav = new ModelAndView("config/users/detail");
		mav.addObject(user);
		mav.addObject("lastUser", lastAdmin);
		mav.addObject("isThisUser", isThisUser);
		mav.addObject("groupString", groupString);
		return mav;
	}

	@RequestMapping("/{userId}/delete")
	public String deleteUser(@PathVariable("userId") int userId, SessionStatus status) {
		// TODO - fix delete functionality - should just disable a user
		User user = userService.loadUser(userId);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		
		boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
		
		if (user != null) {
			if (userService.isAdmin(user) && 
					1 == userService.countActiveAdmins()) {
				return "redirect:/configuration/users/" + userId;
			} else {
				userService.delete(user);
				
				status.setComplete();
								
				if (isThisUser) {
					return "redirect:/j_spring_security_logout";
				} else {
					return "redirect:/configuration/users";
				}
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
	}
}