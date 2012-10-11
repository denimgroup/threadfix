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

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/roles")
@SessionAttributes("role")
public class RolesController {

	private final SanitizedLogger log = new SanitizedLogger(RolesController.class);

	private RoleService roleService;
	
	@Autowired
	public RolesController(RoleService roleService) {
		this.roleService = roleService;
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String [] { "name", "displayName" } );
	}

	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		model.addAttribute("roleList", roleService.loadAll());
		return "config/roles/index";
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.GET)
	public String newForm(Model model) {
		model.addAttribute("role", new Role());
		return "config/roles/form";
	}

	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String newSubmit(HttpServletRequest request, Model model,
			@Valid @ModelAttribute Role role, BindingResult result,
			SessionStatus status) {
		
		roleService.validateRole(role, result);

		if (result.hasErrors()) {
			model.addAttribute("role", role);
			model.addAttribute("name", role.getName());
			model.addAttribute("displayName", role.getDisplayName());
			return "config/roles/form";
		}
		
		role.setName(role.getName().trim());
		role.setDisplayName(role.getDisplayName().trim());
		
		status.setComplete();
		roleService.storeRole(role);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		log.debug(currentUser + " has created a Role with the name" + role.getName() +
				", and the ID " + role.getId());
		return "redirect:/configuration/roles/" + role.getId() + "/users";
	}
	
	@RequestMapping(value = "/{roleId}/delete", method = RequestMethod.POST)
	public String delete(@PathVariable("roleId") int roleId) {
		Role role = roleService.loadRole(roleId);
		
		if (role!= null) {
			roleService.deactivateRole(roleId);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Role", roleId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/roles";
	}
	
	@RequestMapping(value = "/{roleId}/edit", method = RequestMethod.GET)
	public String edit(@PathVariable("roleId") int roleId, ModelMap model) {
		Role role = roleService.loadRole(roleId);
		
		if (role != null) {
			model.addAttribute("role", role);
			return "config/roles/form";
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", roleId));
			throw new ResourceNotFoundException();
		}
	}
	
	@RequestMapping(value = "/{roleId}/edit", method = RequestMethod.POST)
	public String saveEdit(HttpServletRequest request, 
			@PathVariable("roleId") int roleId, 
			@Valid @ModelAttribute Role role, 
			BindingResult result, SessionStatus status,
			ModelMap model) {
		
		roleService.validateRole(role, result);
		if (result.hasErrors()){
			model.addAttribute("accessGroup", role);
			return "config/roles/form";
		}
		
		if (role.getName() != null) {
			status.setComplete();
			roleService.storeRole(role);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", roleId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/roles";
	}
}
