////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.Group;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
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
import java.util.*;

import static com.denimgroup.threadfix.data.entities.Permission.CAN_MANAGE_GROUPS;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;
import static com.denimgroup.threadfix.service.util.PermissionUtils.hasGlobalPermission;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

/**
 * @author dshannon
 * @author mcollins
 */
@Controller
@SessionAttributes({"user", "role", "editRole"})
public class UsersController {

	@Autowired
	private UserService userService = null;
	@Autowired
	private RoleService roleService = null;
	@Autowired
	private OrganizationService organizationService = null;
	@Autowired(required = false)
	private SessionService sessionService;
	@Autowired(required = false)
	private GroupService groupService;
	@Autowired(required = false)
	LdapService ldapService;

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

	@PreAuthorize("hasRole('ROLE_ENTERPRISE') AND hasRole('ROLE_CAN_MANAGE_ROLES')")
	@RequestMapping(value="/configuration/roles")
	public String rolesIndex(ModelMap model, HttpServletRequest request) {
		return indexInner(model, request, "roles");
	}

	@PreAuthorize("hasRole('ROLE_ENTERPRISE') AND hasRole('ROLE_CAN_MANAGE_GROUPS')")
	@RequestMapping(value="/configuration/groups")
	public String groupsIndex(ModelMap model, HttpServletRequest request) {
		return indexInner(model, request, "groups");
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_USERS')")
	@RequestMapping(value="/configuration/users", method = RequestMethod.GET)
	public String index(ModelMap model, HttpServletRequest request) {

		return indexInner(model, request, "users");
	}

	private String indexInner(ModelMap model, HttpServletRequest request, String defaultTab) {
		model.addAttribute("ldap_plugin", EnterpriseTest.isEnterprise());

		model.addAttribute("startingTab", defaultTab);
		model.addAttribute("user", new User());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));

		if (EnterpriseTest.isEnterprise()) {
			model.addAttribute("accessControlMapModel", new AccessControlMapModel());
			model.addAttribute("group", new Group());
			model.addAttribute("editGroup", new Group());
			model.addAttribute("role", new Role());
			model.addAttribute("editRole", new Role());
			return "config/users/enterprise/index";
		} else {
			return "config/users/community/index";
		}
	}

    @RequestMapping(value = "/configuration/users/all", method = RequestMethod.GET)
    @JsonView(AllViews.TableRow.class)
    @ResponseBody
    public RestResponse<List<User>> getUsers() {
        List<User> users = userService.loadAllUsers();
        return success(users);
    }

	@RequestMapping(value = "/configuration/users/map/page/{page}/{numberToShow}", method = RequestMethod.GET)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object map(@PathVariable int page, @PathVariable int numberToShow) {
        List<User> users = userService.retrievePage(page, numberToShow);

		List<User> allUsers = userService.loadAllUsers();

        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();

        for (User user : users) {
            user.setIsDeletable(userService.canDelete(user));
            user.setIsThisUser(currentUser != null && currentUser.equals(user.getName()));
        }

        Map<String, Object> returnMap = new HashMap<>();

        returnMap.put("users", users);
		returnMap.put("allUsers", allUsers);

		if (EnterpriseTest.isEnterprise()) {
			returnMap.put("roles", roleService.loadAllWithCanDeleteSet());

			List<Group> groups = groupService == null ?
					null :
					groupService.loadAllActive();
			returnMap.put("groups", groups);
		}

		returnMap.put("countUsers", userService.countUsers(null));
		returnMap.put("teams", organizationService.loadAllActive());

		Set<EventAction> eventNotificationTypes = EnumSet.copyOf(EventAction.globalEventActions);
		eventNotificationTypes.addAll(EventAction.globalGroupedEventActions);
		Map<String, String> eventNotificationTypeDisplayNames = new HashMap<>();
		for (EventAction eventNotificationType : eventNotificationTypes) {
			eventNotificationTypeDisplayNames.put(eventNotificationType.name(), eventNotificationType.getDisplayName());
		}
		returnMap.put("eventNotificationTypes", eventNotificationTypes);
		returnMap.put("eventNotificationTypeDisplayNames", eventNotificationTypeDisplayNames);

		Map<Integer, Map<String, Boolean>> userEventNotificationSettings = userService.getUserEventNotificationSettings(users);
		returnMap.put("userEventNotificationSettings", userEventNotificationSettings);

		if (ldapService != null) {
			User dbUser = userService.getCurrentUser();

			String currentName = getContext().getAuthentication().getName();

			boolean canManageGroups = hasGlobalPermission(CAN_MANAGE_GROUPS);

			// if the database user is null or is an ldap user, the user logged in with LDAP
			boolean isLdapUser =
					dbUser == null ||
							!currentName.equals(dbUser.getName()) ||
							dbUser.getIsLdapUser();

			returnMap.put("canImportLDAPGroups", canManageGroups && isLdapUser && ldapService.hasValidADConfiguration());
		}

		return success(returnMap);
    }

	@RequestMapping(value = "/configuration/users/search", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object search(HttpServletRequest request) {

		List<User> users = userService.search(request);

        String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();

        for (User user : users) {
            user.setIsDeletable(userService.canDelete(user));
            user.setIsThisUser(currentUser != null && currentUser.equals(user.getName()));
        }

		return success(CollectionUtils.map(
				"users", users,
				"countUsers", userService.countUsers(request.getParameter("searchString"))
		));
    }

	@RequestMapping("/configuration/users/{userId}/delete")
	@ResponseBody
	public RestResponse<String> deleteUser(@PathVariable("userId") int userId,
			HttpServletRequest request, SessionStatus status, Model model) {
		User user = userService.loadUser(userId);
		
		if (user != null) {
			String userName = user.getName();

			if (userService.canDelete(user)) {

				model.addAttribute("user", new User());

				String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
				
				boolean isThisUser = currentUser != null && currentUser.equals(user.getName());
				
				userService.delete(user);
				
				if (isThisUser) {
					SecurityContextHolder.clearContext();

					return success("You have deleted yourself.");
				} else {

					if (sessionService != null) {
						sessionService.invalidateSessions(user);
					}
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