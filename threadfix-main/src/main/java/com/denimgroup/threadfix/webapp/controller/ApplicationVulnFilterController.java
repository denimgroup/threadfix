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

import com.denimgroup.threadfix.data.entities.VulnerabilityFilter;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import java.util.Map;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/filters")
@SessionAttributes("vulnerabilityFilter")
public class ApplicationVulnFilterController extends AbstractVulnFilterController {

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("sourceGenericVulnerability.name", "targetGenericSeverity.id");
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(@PathVariable int appId, Model model) {
		return indexBackend(model, -1, appId);
	}
	
	@RequestMapping(value = "/tab", method = RequestMethod.GET)
	public String tab(@PathVariable int appId, Model model) {
		return tabBackend(model, -1, appId);
	}
	
	@RequestMapping(value = "/new", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<VulnerabilityFilter> submitNew(@PathVariable int appId,
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status) {
		return submitNewBackend(vulnerabilityFilter, bindingResult, status, -1, appId);
	}

	@RequestMapping(value = "/map", method = RequestMethod.GET)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<Map<String, Object>> map(@PathVariable int appId, @PathVariable int orgId) {
		return mapBackend(orgId, appId);
	}
	
	@RequestMapping(value = "/{filterId}/edit", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<VulnerabilityFilter> submitEdit(
			@PathVariable int appId,
			@PathVariable int filterId,
			VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult,
			SessionStatus status) {
		return submitEditBackend(vulnerabilityFilter, bindingResult, status, -1, appId, filterId);
	}
	
	@RequestMapping(value = "/{filterId}/delete", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public String submitDelete(
			@PathVariable int appId,
			@PathVariable int filterId,
			Model model) {
		return submitDeleteBackend(model, -1, appId, filterId);
	}
}
