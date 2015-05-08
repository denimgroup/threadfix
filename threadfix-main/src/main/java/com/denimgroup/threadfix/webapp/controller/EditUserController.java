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

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/configuration/users/{userId}/edit")
@SessionAttributes("user")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class EditUserController {

	private UserService userService = null;
	private RoleService roleService = null;
	private boolean ldapPluginInstalled = false;

	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@Autowired
	public EditUserController(RoleService roleService, UserService userService) {
		this.userService = userService;
		this.roleService = roleService;
		ldapPluginInstalled = EnterpriseTest.isEnterprise();
	}

	public EditUserController(){}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if(ldapPluginInstalled && EnterpriseTest.isEnterprise()){
			dataBinder.setAllowedFields("name", "displayName", "globalRole.id", "unencryptedPassword",
					"passwordConfirm", "hasGlobalGroupAccess", "isLdapUser");
		} else if(ldapPluginInstalled) {
			dataBinder.setAllowedFields("name", "displayName", "globalRole.id", "unencryptedPassword",
					"passwordConfirm", "isLdapUser");
		} else if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("name", "displayName", "globalRole.id", "unencryptedPassword",
					"passwordConfirm", "hasGlobalGroupAccess");
		} else {
			dataBinder.setAllowedFields("name", "displayName", "globalRole.id", "unencryptedPassword",
					"passwordConfirm", "hasGlobalGroupAccess");
		}
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(method = RequestMethod.POST)
	@ResponseBody
	public Object processEdit(@PathVariable("userId") int userId,
							  @ModelAttribute User user,
							  BindingResult result,
							  HttpServletRequest request,
							  Model model) {

		userService.applyChanges(user, userId);

		new UserValidator(roleService).validate(user, result);

		if (userService.hasRemovedAdminPermissions(user) && !userService.canRemoveAdminPermissions(user)) {
			return RestResponse.failure("This would leave users unable to access the user management portion of ThreadFix.");
		}

		if (result.hasErrors()) {
			return FormRestResponse.failure("Errors", result);
		} else {

			User databaseUser = userService.loadUser(user.getName());
			if (databaseUser != null && !databaseUser.getId().equals(user.getId())) {
				result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
                return FormRestResponse.failure("Errors", result);
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
			if (!hasGlobalGroup) {
				user.setGlobalRole(null);
			}
			userService.storeUser(user);

			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
            String userName = user.getName();

			// For now, we'll say that if the name matches then they are the same.
			// This may not hold for AD scenarios.
			log.info("The User " + userName + " (id=" + user.getId() + ") has been edited by user " + currentUser);

            // clear user details from session attribute
			model.addAttribute("user", new User());

			return RestResponse.success(userService.loadAllUsers());
		}
	}
}
