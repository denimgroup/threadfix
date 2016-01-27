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

import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.EmailListService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScheduledEmailReportService;
import com.denimgroup.threadfix.service.email.EmailConfiguration;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Controller
@RequestMapping("/configuration/scheduledEmailReports")
public class ScheduledEmailReportController {

	@Autowired
	private ScheduledEmailReportService scheduledEmailReportService;
	@Autowired
	private OrganizationService organizationService;
	@Autowired
	private GenericSeverityService genericSeverityService;
	@Autowired
	private EmailConfiguration emailConfiguration;
	@Autowired
	private EmailListService emailListService;

    @RequestMapping(method = RequestMethod.GET)
    public String aboutPage() {
        return "config/scheduledemailreports/index";
    }

	@RequestMapping(value="/info", method = RequestMethod.GET)
	@JsonView(AllViews.ScheduledEmailReportView.class)
	public @ResponseBody RestResponse<Map<String, Object>> retrieveExistingSchedules(){
		Map<String, Object> map = map();
		map.put("scheduledEmailReports", scheduledEmailReportService.loadAll());
		map.put("genericSeverities", genericSeverityService.loadAll());
		map.put("organizations", organizationService.loadAll());
		map.put("isConfiguredEmail", emailConfiguration.isConfiguredEmail());
		map.put("emailLists", emailListService.loadAllActive());
		return RestResponse.success(map);
	}
}
