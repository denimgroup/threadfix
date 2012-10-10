package com.denimgroup.threadfix.webapp.controller;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.service.AccessGroupService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/groups")
@SessionAttributes("accessGroup")
public class AccessGroupsController {

	private final SanitizedLogger log = new SanitizedLogger(AccessGroupsController.class);

	private AccessGroupService groupService;
	private OrganizationService teamService;
	
	@Autowired
	public AccessGroupsController(AccessGroupService groupService,
			OrganizationService teamService) {
		this.groupService = groupService;
		this.teamService = teamService;
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String [] { "name", "parentGroup.id", "team.id" } );
	}

	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute("groupList", groupService.loadAll());
		return "config/groups/index";
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.GET)
	public String newForm(Model model) {
		model.addAttribute("groups", groupService.loadAll());
		model.addAttribute("teams", teamService.loadAllActive());
		model.addAttribute("accessGroup", new AccessGroup());
		return "config/groups/form";
	}

	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String newSubmit(HttpServletRequest request, Model model,
			@Valid @ModelAttribute AccessGroup accessGroup, BindingResult result,
			SessionStatus status) {
		
		groupService.validate(accessGroup, result);

		if (result.hasErrors()) {
			model.addAttribute("groups", groupService.loadAll());
			model.addAttribute("teams", teamService.loadAllActive());
			model.addAttribute("accessGroup", accessGroup);
			model.addAttribute("name", accessGroup.getName());
			return "config/groups/form";
		}
		
		accessGroup.setName(accessGroup.getName().trim());
		
		status.setComplete();
		groupService.storeGroup(accessGroup);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		log.debug(currentUser + " has created a group with the name" + accessGroup.getName() +
				", and the ID " + accessGroup.getId());
		return "redirect:/configuration/groups/" + accessGroup.getId() + "/users";
	}
	
	@RequestMapping(value = "/{groupId}/delete", method = RequestMethod.POST)
	public String delete(@PathVariable("groupId") int groupId) {
		AccessGroup newGroup = groupService.loadGroup(groupId);
		
		if (newGroup != null) {
			groupService.deactivateGroup(newGroup);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("API Key", groupId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/groups";
	}
	
	@RequestMapping(value = "/{groupId}/edit", method = RequestMethod.GET)
	public String edit(@PathVariable("groupId") int groupId, ModelMap model) {
		AccessGroup group = groupService.loadGroup(groupId);
		
		if (group != null) {
			model.addAttribute("groups", groupService.loadAll());
			model.addAttribute("teams", teamService.loadAllActive());
			model.addAttribute("accessGroup", group);
			return "config/groups/form";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", groupId));
			throw new ResourceNotFoundException();
		}
	}
	
	@RequestMapping(value = "/{groupId}/edit", method = RequestMethod.POST)
	public String saveEdit(HttpServletRequest request, 
			@PathVariable("groupId") int groupId, 
			@Valid @ModelAttribute AccessGroup accessGroup, 
			BindingResult result, SessionStatus status,
			ModelMap model) {
		
		groupService.validate(accessGroup, result);
		if (result.hasErrors()){
			model.addAttribute("groups", groupService.loadAll());
			model.addAttribute("teams", teamService.loadAllActive());
			model.addAttribute("accessGroup", accessGroup);
			model.addAttribute("name",accessGroup.getName());
			return "config/groups/form";
		}
		
		if (accessGroup.getName() != null) {
			status.setComplete();
			groupService.storeGroup(accessGroup);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", groupId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/groups";
	}

	
}
