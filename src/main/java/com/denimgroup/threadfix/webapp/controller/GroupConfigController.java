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

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.AccessGroupService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.webapp.viewmodels.UserMapsModel;

@Controller
@RequestMapping("/configuration/groups/{groupId}")
@SessionAttributes("groupModel")
public class GroupConfigController {
	
	private UserService userService = null;
	private AccessGroupService groupService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(AddApplicationChannelController.class);

	@Autowired
	public GroupConfigController(UserService userService,
			AccessGroupService groupService) {
		this.groupService = groupService;
		this.userService = userService;
	}

	@RequestMapping(method = RequestMethod.GET, value = "/users")
	public String setupUsersForm(@PathVariable("groupId") int groupId, Model model) {
		AccessGroup group = groupService.loadGroup(groupId);
		List<User> users = groupService.getUsersForGroup(groupId);
		
		List<Integer> activeIds = new ArrayList<Integer>();
		
		if (users != null && users.size() > 0) {
			for (User user : users) {
				activeIds.add(user.getId());
			}
		}
		
		model.addAttribute("group",group);
		model.addAttribute("activeIds", activeIds);
		model.addAttribute("allUsers", userService.loadAllUsers());
		model.addAttribute("groupModel", new UserMapsModel());
		return "config/groups/users";
	}

	@RequestMapping(method = RequestMethod.POST, value = "/users")
	public String processUsersForm(@PathVariable("groupId") int groupId, 
			@ModelAttribute UserMapsModel groupModel,
			Model model) {
		
		if (groupModel.getObjectIds() == null
				|| groupModel.getObjectIds().size() == 0) {
			log.info("Removing all groups from group " + groupId);
		}

		groupService.addUsersToGroup(groupId, groupModel.getObjectIds());
		
		return "redirect:/configuration/groups/";
	}
}
