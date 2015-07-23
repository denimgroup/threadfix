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

import com.denimgroup.threadfix.data.entities.ChannelVulnerabilityFilter;
import com.denimgroup.threadfix.data.entities.VulnerabilityFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
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
@RequestMapping("/configuration/filters")
@SessionAttributes({"vulnerabilityFilter", "severityFilter", "channelVulnerabilityFilter"})
public class GlobalFilterController extends AbstractVulnFilterController {

	private final SanitizedLogger log = new SanitizedLogger(GlobalFilterController.class);

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("sourceGenericVulnerability.name", "targetGenericSeverity.id", "targetGenericSeverity.name", "targetGenericSeverity.displayName", "sourceChannelType.id", "sourceChannelType.name", "sourceChannelVulnerability.id", "sourceChannelVulnerability.name");
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		return indexBackend(model, -1, -1);
	}
	
	@RequestMapping(value = "/tab", method = RequestMethod.GET)
	public String tab(Model model) {
		return tabBackend(model, -1, -1);
	}

	@RequestMapping(value = "/map", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Map<String, Object>> map() {
		return mapBackend(-1, -1);
	}

	@RequestMapping(value="/new", method = RequestMethod.POST)
	public @ResponseBody RestResponse<VulnerabilityFilter> submitNew(VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult, SessionStatus status, Model model) {
		return submitNewBackend(vulnerabilityFilter,
				bindingResult, status, -1, -1);
	}

	@RequestMapping(value="/{filterId}/edit", method = RequestMethod.POST)
	public @ResponseBody RestResponse<VulnerabilityFilter> submitEdit(VulnerabilityFilter vulnerabilityFilter,
			BindingResult bindingResult, SessionStatus status, Model model,
			@PathVariable int filterId) {
		return submitEditBackend(vulnerabilityFilter,
				bindingResult, status,
				-1, -1, filterId);
	}

	@RequestMapping(value="/{filterId}/delete", method = RequestMethod.POST)
	public String submitDelete(Model model, @PathVariable int filterId) {
		return submitDeleteBackend(model, -1, -1, filterId);
	}

	@RequestMapping(value="/newChannelFilter", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<ChannelVulnerabilityFilter> submitNewChannelFilter(ChannelVulnerabilityFilter channelVulnerabilityFilter,
																	 BindingResult bindingResult, SessionStatus status) {
		if (!EnterpriseTest.isEnterprise()) {
			String msg = "You do not have permission to add new channel vulnerability filter. You need to update to enterprise license.";
			log.warn(msg);
			return RestResponse.failure(msg);
		}
		return submitNewChannelFilterBackend(channelVulnerabilityFilter,
				bindingResult, status);
	}

	@RequestMapping(value="/{filterId}/editChannelFilter", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<ChannelVulnerabilityFilter> submitEditChannelFilter(ChannelVulnerabilityFilter channelVulnerabilityFilter,
																	  BindingResult bindingResult, SessionStatus status, Model model,
																	  @PathVariable int filterId) {
		if (!EnterpriseTest.isEnterprise()) {
			String msg = "You do not have permission to edit channel vulnerability filter. You need to update to enterprise license.";
			log.warn(msg);
			return RestResponse.failure(msg);
		}
		return submitEditChannelFilterBackend(channelVulnerabilityFilter,
				bindingResult, status, filterId);
	}

	@RequestMapping(value="/{filterId}/deleteChannelFilter", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public @ResponseBody RestResponse<String> submitDeleteChannelFilter(@PathVariable int filterId) {
		if (!EnterpriseTest.isEnterprise()) {
			String msg = "You do not have permission to delete channel vulnerability filter. You need to update to enterprise license.";
			log.warn(msg);
			return RestResponse.failure(msg);
		}
		return RestResponse.success(submitDeleteChannelFilterBackend(filterId));
	}
}
