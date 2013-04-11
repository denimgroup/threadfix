package com.denimgroup.threadfix.webapp.controller;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
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
@SessionAttributes({"editRole", "role"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_ROLES')")
public class RolesController {

	private final SanitizedLogger log = new SanitizedLogger(RolesController.class);

	private RoleService roleService;
	
	@Autowired
	public RolesController(RoleService roleService) {
		this.roleService = roleService;
	}
	
	public RolesController(){}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields((String[])ArrayUtils.add(Role.ALL_PERMISSIONS, "displayName"));
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		
		List<Role> roles = roleService.loadAll();

		for (Role listRole : roles) {
			listRole.setCanDelete(roleService.canDelete(listRole));
		}
		
		model.addAttribute("roleList", roles);
		model.addAttribute("role", new Role());
		model.addAttribute("editRole", new Role());
		return "config/roles/index";
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String newSubmit(HttpServletRequest request, Model model,
			@Valid @ModelAttribute Role role, BindingResult result,
			SessionStatus status) {
		role.setId(null);
		
		String resultString = roleService.validateRole(role, result);
		if (!resultString.equals(RoleService.SUCCESS)) {
			model.addAttribute("errorMessage", resultString);
			model.addAttribute("editRole", role);
			model.addAttribute("contentPage", "config/roles/newForm.jsp");
			return "ajaxFailureHarness";
		}
		
		role.setDisplayName(role.getDisplayName().trim());
		
		roleService.storeRole(role);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		log.debug(currentUser + " has created a Role with the name" + role.getDisplayName() +
				", and the ID " + role.getId());

		List<Role> roles = roleService.loadAll();

		for (Role listRole : roles) {
			listRole.setCanDelete(roleService.canDelete(listRole));
		}
		
		model.addAttribute("roleList", roles);
		
		model.addAttribute("contentPage", "config/roles/rolesTable.jsp");
		return "ajaxSuccessHarness";
	}
	
	@RequestMapping(value = "/{roleId}/delete", method = RequestMethod.POST)
	public String delete(@PathVariable("roleId") int roleId) {
		Role role = roleService.loadRole(roleId);
		
		if (role != null) {
			if (roleService.canDelete(role)) {
				roleService.deactivateRole(roleId);
			} else {
				return "redirect:/configuration/roles";
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Role", roleId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/roles";
	}
	
	@RequestMapping(value = "/{roleId}/edit", method = RequestMethod.POST)
	public String saveEdit(HttpServletRequest request,
			@PathVariable("roleId") int roleId,
			@Valid @ModelAttribute Role role,
			BindingResult result, SessionStatus status,
			ModelMap model) {
		
		role.setId(roleId);
		
		String resultString = roleService.validateRole(role, result);
		if (!resultString.equals(RoleService.SUCCESS)) {
			model.addAttribute("errorMessage", resultString);
			model.addAttribute("editRole", role);
			model.addAttribute("contentPage", "config/roles/form.jsp");
			return "ajaxFailureHarness";
		}
		
		if (role.getDisplayName() != null) {
			roleService.storeRole(role);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", roleId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/roles";
	}
}
