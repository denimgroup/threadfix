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

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.importer.util.JsonUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;


@Controller
@RequestMapping("/mappings/channelSeverity")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_SYSTEM_SETTINGS')")
public class ChannelSeverityMappingsController {

	private final SanitizedLogger log = new SanitizedLogger(ChannelSeverityMappingsController.class);

	@Autowired
	private ChannelSeverityService channelSeverityService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index() {
		return "mappings/channelSeverityIndex";
	}

	@RequestMapping(value = "/map", method = RequestMethod.GET)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object getMap() {
		return RestResponse.success(map(
				"genericSeverities", genericSeverityService.loadAll(),
				"channelTypesData", channelSeverityService.loadAllByChannel()));
	}


	@RequestMapping(value = "/update", method = RequestMethod.POST)
	@ResponseBody
	public RestResponse<String> update(HttpServletRequest request) {
		String list = request.getParameter("updatedChannelSeverities");
		List<ChannelSeverity> severities;
		try {
			severities = JsonUtils.toObjectList(list, ChannelSeverity.class);
			channelSeverityService.updateChannelSeverityMappings(severities);
		} catch (JSONException e) {
			e.printStackTrace();
		}
		String str = request.getParameter("str");
		return RestResponse.success("blablablablabla");
	}

}

