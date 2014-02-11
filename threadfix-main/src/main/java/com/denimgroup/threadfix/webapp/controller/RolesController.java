////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.EnterpriseTest;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.apache.commons.lang.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/configuration/roles")
@SessionAttributes({"editRole", "role"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_ROLES')")
public class RolesController {

	private final SanitizedLogger log = new SanitizedLogger(RolesController.class);

    @Autowired
	private RoleService roleService;

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields((String[])ArrayUtils.add(Role.ALL_PERMISSIONS, "displayName"));
		}
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		
		List<Role> roles = roleService.loadAll();

		for (Role listRole : roles) {
			listRole.setCanDelete(roleService.canDelete(listRole));
		}
		
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));
		model.addAttribute("roleList", roles);
		model.addAttribute("role", new Role());
		model.addAttribute("editRole", new Role());
		return "config/roles/index";
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String newSubmit(Model model, @Valid @ModelAttribute Role role, 
			BindingResult result, SessionStatus status,
			HttpServletRequest request) {
		role.setId(null);
		
		String resultString = roleService.validateRole(role, result);
		if (!resultString.equals(RoleService.SUCCESS)) {
			if (!resultString.equals(RoleService.FIELD_ERROR)) {
				model.addAttribute("errorMessage", resultString);
			}
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
		ControllerUtils.addSuccessMessage(request, 
				"Role " + role.getDisplayName() + " was created successfully.");
		
		model.addAttribute("contentPage","/configuration/roles");
		return "ajaxRedirectHarness";
	}
	
	@RequestMapping(value = "/{roleId}/delete", method = RequestMethod.POST)
	public String delete(@PathVariable("roleId") int roleId,
			HttpServletRequest request) {
		Role role = roleService.loadRole(roleId);
		
		if (role != null) {
			String roleName = role.getDisplayName();
			if (roleService.canDelete(role)) {
				roleService.deactivateRole(roleId);
				ControllerUtils.addSuccessMessage(request, 
						"Role " + roleName + " was deleted successfully.");
			} else {
				ControllerUtils.addErrorMessage(request, 
						"Role " + roleName + " was not deleted successfully.");
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Role", roleId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/configuration/roles";
	}
	
	@RequestMapping(value = "/{roleId}/edit", method = RequestMethod.POST)
	public String saveEdit(@PathVariable("roleId") int roleId,
			@Valid @ModelAttribute Role role,
			BindingResult result, SessionStatus status,
			ModelMap model, HttpServletRequest request) {
		
		role.setId(roleId);
		
		String resultString = roleService.validateRole(role, result);
		if (!resultString.equals(RoleService.SUCCESS)) {
			if (!resultString.equals(RoleService.FIELD_ERROR)) {
				model.addAttribute("errorMessage", resultString);
			}
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
		
		ControllerUtils.addSuccessMessage(request, 
				"Role " + role.getDisplayName() + " was edited successfully.");
		
		model.addAttribute("contentPage","/configuration/roles");
		return "ajaxRedirectHarness";
	}
}
