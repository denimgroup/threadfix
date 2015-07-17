////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.ThreadFixUserDetails;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.validator.UserValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.List;

@Controller
@RequestMapping("/configuration/users/password")
@SessionAttributes("user")
public class ChangePasswordController {

    private static final String CURRENT_PASSWORD_FIELD_STR = "currentPassword",
                                PASSWORD_FIELD_STR = "password";

	private UserService userService = null;
	private RoleService roleService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@Autowired
	public ChangePasswordController(RoleService roleService,
			UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("currentPassword", "unencryptedPassword", "passwordConfirm");
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView editForm(HttpServletRequest request) {

		User user = null;
		Integer userId = null;
		Object auth = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		if (auth instanceof ThreadFixUserDetails) {
			userId = ((ThreadFixUserDetails) auth).getUserId();
			user = userService.loadUser(userId);
		}

		if (user == null) {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}

		Object successMessage = ControllerUtils.getSuccessMessage(request);
		Object errorMessage = ControllerUtils.getErrorMessage(request);


		ModelAndView mav = new ModelAndView("config/users/password");
		mav.addObject(user);
		mav.addObject("successMessage", successMessage);
        mav.addObject("errorMessage", errorMessage);
        mav.addObject(CURRENT_PASSWORD_FIELD_STR, ControllerUtils.getItem(request, CURRENT_PASSWORD_FIELD_STR));
        mav.addObject(PASSWORD_FIELD_STR, ControllerUtils.getItem(request, PASSWORD_FIELD_STR));
		return mav;
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processEdit(@ModelAttribute User user,
			BindingResult result, SessionStatus status, HttpServletRequest request) {
		new UserValidator(roleService).validate(user, result);
		if (result.hasErrors()) {
            ControllerUtils.addErrorMessage(request, "Error!!!");
            return "redirect:/configuration/users/password";
		} else {
			
			if (user.getUnencryptedPassword() == null || 
					user.getUnencryptedPassword().trim().equals("")) {
                ControllerUtils.addItem(request, PASSWORD_FIELD_STR, "You must enter a new password.");
                return "redirect:/configuration/users/password";
			}
			
			String currentUserName = SecurityContextHolder.getContext().getAuthentication().getName();

            for (User databaseUser : userService.loadUser(user.getName())) {
                if (!databaseUser.getId().equals(user.getId())) {
                    ControllerUtils.addItem(request, CURRENT_PASSWORD_FIELD_STR, "The user has changed since starting this procedure.");
                    return "redirect:/configuration/users/password";
                }
            }

            User databaseUser = userService.loadUser(user.getId());
			if (userService.isCorrectPassword(databaseUser, user.getCurrentPassword())) {
				user.setHasChangedInitialPassword(true);
				user.setLastPasswordChangedDate(new Date());
				Object currentUserObject = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
				if (currentUserObject instanceof ThreadFixUserDetails) {
					ThreadFixUserDetails details = (ThreadFixUserDetails) currentUserObject;
					details.setHasChangedInitialPassword(true);
				}
				userService.storeUser(user);
				status.setComplete();
				log.info("The User " + currentUserName + " has completed the password change.");
				ControllerUtils.addSuccessMessage(request, "The password change was successful.");
				return "redirect:/configuration/users/password";
				
			} else {
				log.info("An incorrect password was submitted during a password change attempt.");
                ControllerUtils.addItem(request, CURRENT_PASSWORD_FIELD_STR, "That was not the correct password.");
                return "redirect:/configuration/users/password";
			}
		}
	}
	
}
