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
@RequestMapping("/configuration/users/{userId}/roles")
@SessionAttributes("userModel")
public class UserRolesConfigController {
	
	private UserService userService = null;
	private RoleService roleService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(UserRolesConfigController.class);

	@Autowired
	public UserRolesConfigController(UserService userService,
			RoleService roleService) {
		this.userService = userService;
		this.roleService = roleService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(@PathVariable("userId") int userId, Model model) {
		User user = userService.loadUser(userId);
		List<Role> roles = roleService.getRolesForUser(userId);
		
		List<Integer> activeIds = new ArrayList<Integer>();
		
		if (roles != null && roles.size() > 0) {
			for (Role role : roles) {
				activeIds.add(role.getId());
			}
		}
		
		model.addAttribute(user);
		model.addAttribute("activeIds", activeIds);
		model.addAttribute("allRoles", roleService.loadAll());
		model.addAttribute("userModel", new UserMapsModel());
		return "config/users/roles";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processNew(@PathVariable("userId") int userId, 
			@ModelAttribute UserMapsModel userModel,
			Model model) {

		if (!userService.canSetRoles(userId, userModel.getObjectIds())) {
			model.addAttribute("error", "You cannot remove those roles from this user.");
			return setupForm(userId, model);
		}

		if (userModel.getObjectIds() == null
				|| userModel.getObjectIds().size() == 0) {
			log.info("Removing all roles from user " + userId);
		}

		roleService.setRolesForUser(userId, userModel.getObjectIds());
		
		return "redirect:/configuration/users";
	}
}
