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
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
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
    @Autowired
    private UserService userService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new BeanValidator());
    }

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        if (EnterpriseTest.isEnterprise()) {
            dataBinder.setAllowedFields((String[]) ArrayUtils.add(Role.ALL_PERMISSIONS, "displayName"));
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
        model.addAttribute("role", new Role());
        model.addAttribute("editRole", new Role());
        return "config/roles/index";
    }


    @RequestMapping(value = "list", method = RequestMethod.GET)
    public @ResponseBody RestResponse<List<Role>> map() {

        List<Role> roles = roleService.loadAll();

        for (Role listRole : roles) {
            listRole.setCanDelete(roleService.canDelete(listRole));
        }

        return RestResponse.success(roles);
    }

    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Role> newSubmit(Model model, @Valid @ModelAttribute Role role,
                                 BindingResult result) {
        role.setId(null);

        String resultString = roleService.validateRole(role, result);
        if (!resultString.equals(RoleService.SUCCESS)) {
            if (!resultString.equals(RoleService.FIELD_ERROR)) {
                model.addAttribute("errorMessage", resultString);
            }
            model.addAttribute("editRole", role);
            model.addAttribute("contentPage", "config/roles/newForm.jsp");
            return FormRestResponse.failure("Found some errors", result);
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

        return RestResponse.success(role);
    }

    @RequestMapping(value = "/{roleId}/delete", method = RequestMethod.POST)
	public @ResponseBody Object delete(@PathVariable("roleId") int roleId) {
		Role role = roleService.loadRole(roleId);
		
		if (role != null) {
			String roleName = role.getDisplayName();
			if (roleService.canDelete(role)) {
                boolean shouldForceLogout = userService.shouldReloadUserIfRoleChanged(role);

				roleService.deactivateRole(roleId);

                if (shouldForceLogout) {
                    // This invalidates the current session
                    SecurityContextHolder.getContext().setAuthentication(null);
                    // TODO improve this system.
                    return RestResponse.success("Role was deleted successfully. " +
                            "Your session has been invalidated and you should be redirected to the login page now.");
                }

                return RestResponse.success("Role " + roleName + " was deleted successfully.");
			} else {
				return RestResponse.failure("Role " + roleName + " was not deleted successfully.");
			}
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Role", roleId));
			throw new ResourceNotFoundException();
		}
	}
	
	@RequestMapping(value = "/{roleId}/edit", method = RequestMethod.POST)
	public @ResponseBody RestResponse<Role> saveEdit(@PathVariable("roleId") int roleId,
			@Valid @ModelAttribute Role role,
			BindingResult result, ModelMap model) {
		
		role.setId(roleId);
		
		String resultString = roleService.validateRole(role, result);
		if (!resultString.equals(RoleService.SUCCESS)) {
			return FormRestResponse.failure(resultString, result);
		}
		
		if (role.getDisplayName() != null) {
			roleService.storeRole(role);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Group", roleId));
			throw new ResourceNotFoundException();
		}
		
		return RestResponse.success(role);
	}
}
