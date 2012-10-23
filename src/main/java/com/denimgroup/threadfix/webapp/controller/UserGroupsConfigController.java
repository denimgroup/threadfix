package com.denimgroup.threadfix.webapp.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessGroupService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.UserMapsModel;

@Controller
@RequestMapping("/configuration/users/{userId}/groups")
@SessionAttributes("userModel")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_GROUPS')")
public class UserGroupsConfigController {
	
	private UserService userService = null;
	private AccessGroupService groupService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddApplicationChannelController.class);

	@Autowired
	public UserGroupsConfigController(UserService userService,
			AccessGroupService groupService) {
		this.userService = userService;
		this.groupService = groupService;
	}
	
	public UserGroupsConfigController(){}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(@PathVariable("userId") int userId, Model model) {
		User user = userService.loadUser(userId);
		List<AccessGroup> groups = groupService.getGroupsForUser(userId);
		
		List<Integer> activeIds = new ArrayList<Integer>();
		
		if (groups != null && groups.size() > 0) {
			for (AccessGroup group : groups) {
				activeIds.add(group.getId());
			}
		}
		
		model.addAttribute(user);
		model.addAttribute("activeIds", activeIds);
		model.addAttribute("allGroups", groupService.loadAll());
		model.addAttribute("userModel", new UserMapsModel());
		return "config/users/groups";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processNew(@PathVariable("userId") int userId, 
			@ModelAttribute UserMapsModel userModel,
			Model model) {
		
		if (userModel.getObjectIds() == null
				|| userModel.getObjectIds().size() == 0) {
			log.info("Removing all groups from user " + userId);
		}

		groupService.setGroupsForUser(userId, userModel.getObjectIds());
		
		return "redirect:/configuration/users";
	}
}
