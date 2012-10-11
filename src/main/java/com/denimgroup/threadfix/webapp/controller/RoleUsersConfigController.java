package com.denimgroup.threadfix.webapp.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.UserMapsModel;

@Controller
@RequestMapping("/configuration/roles/{roleId}")
@SessionAttributes("roleModel")
public class RoleUsersConfigController {
	
	private UserService userService = null;
	private RoleService roleService = null;

	private final SanitizedLogger log = new SanitizedLogger(RoleUsersConfigController.class);

	@Autowired
	public RoleUsersConfigController(UserService userService,
			RoleService roleService) {
		this.roleService = roleService;
		this.userService = userService;
	}

	@RequestMapping(method = RequestMethod.GET, value = "/users")
	public String setupUsersForm(@PathVariable("roleId") int roleId, Model model) {
		Role role = roleService.loadRole(roleId);
		List<User> users = roleService.getUsersForRole(roleId);
		
		List<Integer> activeIds = new ArrayList<Integer>();
		
		if (users != null && users.size() > 0) {
			for (User user : users) {
				activeIds.add(user.getId());
			}
		}
		
		model.addAttribute("role",role);
		model.addAttribute("activeIds", activeIds);
		model.addAttribute("allUsers", userService.loadAllUsers());
		model.addAttribute("roleModel", new UserMapsModel());
		return "config/roles/users";
	}

	@RequestMapping(method = RequestMethod.POST, value = "/users")
	public String processUsersForm(@PathVariable("roleId") int roleId, 
			@ModelAttribute UserMapsModel roleModel,
			Model model) {
		
		Role role = roleService.loadRole(roleId);
		
		boolean hasEmptyRoles = roleModel.getObjectIds() == null || roleModel.getObjectIds().size() == 0;
		boolean isAdmin = role != null && role.getName() != null && role.getName().equals(Role.ADMIN);
		
		if (isAdmin && hasEmptyRoles) {
			model.addAttribute("error", "You cannot remove all users from the Administrator role.");
			return setupUsersForm(roleId, model);
		} else if (hasEmptyRoles) {
			log.info("Removing all roles from role " + roleId);
		}

		roleService.setUsersForRole(roleId, roleModel.getObjectIds());
		
		return "redirect:/configuration/roles/";
	}
}
