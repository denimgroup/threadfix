////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.VulnerabilityFilter;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.VulnerabilityFilterService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/filters")
@SessionAttributes("vulnerabilityFilter")
public class ApplicationVulnFilterController extends AbstractVulnFilterController {
	
	@Autowired
	public ApplicationVulnFilterController(
			PermissionService permissionService,
			SeverityFilterService severityFilterService,
			OrganizationService organizationService,
			VulnerabilityFilterService vulnerabilityFilterService,
			ApplicationService applicationService,
			GenericVulnerabilityService genericVulnerabilityService,
			GenericSeverityService genericSeverityService) {
		super(permissionService, severityFilterService, organizationService, vulnerabilityFilterService,
				applicationService, genericVulnerabilityService, genericSeverityService);
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("sourceGenericVulnerability.name", "targetGenericSeverity.id");
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(@PathVariable int appId, Model model) {
		return indexBackend(model, -1, appId);
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String submitNew(@PathVariable int orgId, @PathVariable int appId,
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			Model model,
			HttpServletRequest request) {
		return submitNewBackend(vulnerabilityFilter, bindingResult, status, model, request, -1, appId);
	}
	
	@RequestMapping(value = "/{filterId}/edit", method = RequestMethod.POST)
	public String submitEdit(
			@PathVariable int appId,
			@PathVariable int filterId,
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status,
			Model model,
			HttpServletRequest request) {
		return submitEditBackend(vulnerabilityFilter, bindingResult, status, model, request, -1, appId, filterId);
	}
	
	@RequestMapping(value = "/{filterId}/delete", method = RequestMethod.POST)
	public String submitDelete(
			@PathVariable int appId,
			@PathVariable int filterId,
			Model model,
			HttpServletRequest request) {
		return submitDeleteBackend(model, request, -1, appId, filterId);
	}
}
