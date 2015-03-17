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
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.denimgroup.threadfix.webapp.validator.UserValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/configuration/users/new")
@SessionAttributes("user")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class AddUserController {

	private UserService userService = null;
	private RoleService roleService = null;
	private boolean ldapPluginInstalled = false;
	
	private final SanitizedLogger log = new SanitizedLogger(AddUserController.class);

	@Autowired
	public AddUserController(
			UserService userService, RoleService roleService) {
		this.roleService = roleService;
		this.userService = userService;
		ldapPluginInstalled = EnterpriseTest.isEnterprise();
	}
	
	public AddUserController(){}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if(ldapPluginInstalled && EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "displayName", "hasGlobalGroupAccess", "isLdapUser");
		} else if (ldapPluginInstalled) {
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "displayName", "isLdapUser");
		} else if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "displayName", "hasGlobalGroupAccess");
		} else {
			dataBinder.setAllowedFields("name", "globalRole.id", "unencryptedPassword", 
					"passwordConfirm", "displayName", "hasGlobalGroupAccess");
		}
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object processNew(@Valid @ModelAttribute User user, BindingResult result, Model model) {
		new UserValidator(roleService).validate(user, result);
		if (result.hasErrors()) {
            return FormRestResponse.failure("Errors", result);
		} else {
			User databaseUser = userService.loadUser(user.getName().trim());
			if (databaseUser != null) {
				result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
                return FormRestResponse.failure("Errors", result);
			}

			userService.setRoleCommunity(user);

            user.setId(null);
			Integer id = userService.createUser(user);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a new User with the name " + user.getName() +
                    ", the ID " + user.getId());

			model.addAttribute("user", new User());
			return RestResponse.success(userService.loadUser(id));
		}
	}
}
