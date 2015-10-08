////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.util.ValidationUtils.HTML_ERROR;
import static com.denimgroup.threadfix.util.ValidationUtils.containsHTML;


@Controller
@RequestMapping("/organizations/{orgId}/edit")
@SessionAttributes("organization")
public class EditOrganizationController {

	private static final SanitizedLogger LOG = new SanitizedLogger(EditOrganizationController.class);

    @Autowired
	private OrganizationService organizationService = null;

	private final SanitizedLogger log = new SanitizedLogger(EditOrganizationController.class);

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name");
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(method = RequestMethod.POST)
	public @ResponseBody Object editSubmit(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Organization organization, BindingResult result) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_TEAMS, orgId, null) ||
				!organization.isActive()) {
			return RestResponse.failure("You don't have permission to edit this team.");
        }
		
		if (result.hasErrors()) {
            return RestResponse.failure("Errors: " + result.getAllErrors());
		} else {
			
			if (organization.getName() == null || organization.getName().trim().isEmpty()) {
                return RestResponse.failure("Name cannot be blank.");
			}

			if (containsHTML(organization.getName())) {
				LOG.error(HTML_ERROR);
				return failure(HTML_ERROR);
			}
			
			Organization databaseOrganization = organizationService.loadByName(organization.getName().trim());
			if (databaseOrganization != null && !databaseOrganization.getId().equals(organization.getId())) {
                return RestResponse.failure("That name is already taken.");
			}
			
			organizationService.saveOrUpdate(organization);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("The Organization " + organization.getName() + " (id=" + organization.getId() + ") has been edited by user " + user);
			
            return RestResponse.success(organizationService.loadById(orgId));
		}
	}

}
