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
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SessionService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.beans.AccessControlMapModel;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * @author dshannon
 * @author mcollins
 */
@Controller
@SessionAttributes({"user", "role", "editRole"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
public class UsersController {

	@Autowired
	private UserService userService = null;
	@Autowired
	private RoleService roleService = null;
	@Autowired
	private OrganizationService organizationService = null;
	@Autowired
	private SessionService sessionService;

	private final SanitizedLogger log = new SanitizedLogger(UsersController.class);

	public UsersController(){}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setDisallowedFields("id");
	}
	
	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@PreAuthorize("hasRole('ROLE_ENTERPRISE')")
	@RequestMapping(value="/configuration/roles")
	public String rolesIndex(ModelMap model, HttpServletRequest request) {
		return indexInner(model, request, "roles");
	}

	@RequestMapping(value="/configuration/users", method = RequestMethod.GET)
	public String index(ModelMap model, HttpServletRequest request) {

		return indexInner(model, request, "users");
	}

	private String indexInner(ModelMap model, HttpServletRequest request, String defaultTab) {
		List<User> users = userService.loadAllUsers();

		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();

		for (User user : users) {
			user.setIsDeletable(userService.canDelete(user));
			user.setIsThisUser(currentUser != null && currentUser.equals(user.getName()));
		}
		model.addAttribute("ldap_plugin", EnterpriseTest.isEnterprise());
		model.addAttribute("users", users);

		model.addAttribute("startingTab", defaultTab);
		model.addAttribute("user", new User());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));

		if (EnterpriseTest.isEnterprise()) {
			model.addAttribute("accessControlMapModel", new AccessControlMapModel());
			model.addAttribute("role", new Role());
			model.addAttribute("editRole", new Role());
			return "config/users/enterprise/index";
		} else {
			return "config/users/community/index";
		}
	}

	@RequestMapping(value = "/configuration/users/map/page/{page}/{numberToShow}", method = RequestMethod.GET)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object map(@PathVariable int page, @PathVariable int numberToShow) {
        List<User> users = userService.retrievePage(page, numberToShow);

        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();

        for (User user : users) {
            user.setIsDeletable(userService.canDelete(user));
            user.setIsThisUser(currentUser != null && currentUser.equals(user.getName()));
        }

        Map<String, Object> returnMap = new HashMap<>();

        returnMap.put("users", users);
        returnMap.put("roles", roleService.loadAll());
		returnMap.put("countUsers", userService.countUsers());
		returnMap.put("teams", organizationService.loadAllActive());

		return success(returnMap);
    }

	@RequestMapping("/configuration/users/{userId}/delete")
	@ResponseBody
	public RestResponse<String> deleteUser(@PathVariable("userId") int userId,
			HttpServletRequest request, SessionStatus status, Model model) {
		User user = userService.loadUser(userId);
		
		if (user != null) {
			String userName = user.getName();

			if (userService.canDelete(user)) {
				
				status.setComplete();

				model.addAttribute("user", new User());

				String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
				
				boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
				
				userService.delete(user);
				
				if (isThisUser) {
					SecurityContextHolder.clearContext();

					return success("You have deleted yourself.");
				} else {

					sessionService.invalidateSessions(user);
					return success("You have successfully deleted " + userName);
				}
			} else {
				return failure("Unable to delete the user.");
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("User", userId));
			throw new ResourceNotFoundException();
		}
	}
}