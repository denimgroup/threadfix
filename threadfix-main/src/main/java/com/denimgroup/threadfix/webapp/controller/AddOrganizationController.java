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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.validation.Valid;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.util.ValidationUtils.HTML_ERROR;
import static com.denimgroup.threadfix.util.ValidationUtils.containsHTML;

@Controller
@RequestMapping("/organizations/modalAdd")
public class AddOrganizationController {

	private static final SanitizedLogger LOG = new SanitizedLogger(AddOrganizationController.class);

    @Autowired
	private OrganizationService organizationService = null;

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name");
	}
	
	@RequestMapping(method = RequestMethod.POST, consumes="application/x-www-form-urlencoded",
            produces="application/json")
	public @ResponseBody Object newSubmit(@Valid @ModelAttribute Organization organization,
                                                               BindingResult result, SessionStatus status,
                                                               Model model) {
        if (!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_TEAMS)) {
            return RestResponse.failure("You don't have permission to add new teams.");
        }

		model.addAttribute("contentPage", "organizations/newTeamForm.jsp");
		if (result.hasErrors()) {
			return RestResponse.failure("Failed to add the team.");
		} else {
			
			if (organization.getName() == null || organization.getName().trim().isEmpty()) {
				result.rejectValue("name", null, null, "This field cannot be blank");
				return RestResponse.failure("Failed to add the team.");
			}

			if (containsHTML(organization.getName())) {
				LOG.error(HTML_ERROR);
				return failure(HTML_ERROR);
			}
			
			if (organizationService.nameExists(organization.getName().trim())) {
				result.rejectValue("name", "errors.nameTaken");
				return RestResponse.failure("That name was already taken.");
			}
			
			organizationService.saveOrUpdate(organization);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			LOG.debug(user + " has created a new Organization with the name " + organization.getName() +
					" and ID " + organization.getId());

			status.setComplete();

            Map<String, Object> map = map();

            map.put("team", organization);
            map.put("canEdit", PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_APPLICATIONS));

			return RestResponse.success(map);
		}
	}
}
