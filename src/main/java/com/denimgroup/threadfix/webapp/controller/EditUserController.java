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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.validator.UserValidator;

@Controller
@RequestMapping("/configuration/users/{userId}/edit")
@SessionAttributes("user")
public class EditUserController {

	private UserService userService = null;
	
	private final Log log = LogFactory.getLog(EditUserController.class);

	@Autowired
	public EditUserController(UserService userService) {
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
		mav.addObject("isThisUser", isThisUser);
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processEdit(@PathVariable("userId") int userId, @ModelAttribute User user,
			BindingResult result, SessionStatus status) {
		new UserValidator().validate(user, result);
		if (result.hasErrors()) {
			return "config/users/form";
		} else {
			
			User databaseUser = userService.loadUser(user.getName());
			if (databaseUser != null && !databaseUser.getId().equals(user.getId())) {
				result.rejectValue("name", "errors.nameTaken");
				return "config/users/form";
			}
			
			boolean isDowngradingPermissions = userService.isAdmin(databaseUser) && 
					!userService.isAdmin(user);
			
			if (isDowngradingPermissions &&
					userService.countActiveAdmins() == 1) {
				log.info("A request was made that would leave ThreadFix with 0 admin users. " +
						"The change will not be saved.");
				result.rejectValue("role.id", null, "This is the last Admin account so it cannot be switched to User.");
				return "config/users/form";
			}
			
			userService.storeUser(user);
			
			status.setComplete();
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			
			// For now, we'll say that if the name matches then they are the same.
			// This may not hold for AD scenarios.
			boolean currentUserEdited = currentUser.equals(user.getName());
			log.info("The User " + user.getName() + " (id=" + user.getId() + ") has been edited by user " + currentUser);

			if (currentUserEdited && databaseUser != null && isDowngradingPermissions) {
				log.info("The current user's permissions have been downgraded. Logging out.");
				return "redirect:/j_spring_security_logout";
			} else {
				return "redirect:/configuration/users/" + userId;
			}
		}
	}
}
