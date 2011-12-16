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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.UserService;

/**
 * @author dshannon
 * 
 */
@Controller
@RequestMapping("/configuration/users")
public class UsersController {

	private UserService userService = null;
	
	private final Log log = LogFactory.getLog(UsersController.class);

	@Autowired
	public UsersController(UserService userService) {
		this.userService = userService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setDisallowedFields(new String[] { "id" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public String manageUsers(ModelMap model) {
		model.addAttribute(userService.loadAllUsers());
		return "config/users/index";
	}

	@RequestMapping("/{userId}")
	public ModelAndView detail(@PathVariable("userId") int userId) {
		User user = userService.loadUser(userId);
		
		if (user == null) {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("config/users/detail");
		mav.addObject(user);
		return mav;
	}

	@RequestMapping("/{userId}/delete")
	public String deleteUser(@PathVariable("userId") int userId, SessionStatus status) {
		// TODO - fix delete functionality - should just disable a user
		User user = userService.loadUser(userId);
		if (user != null) {
			userService.deleteById(userId);
			status.setComplete();
			log.debug("");
			return "redirect:/configuration/users";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
	}
}