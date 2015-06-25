package com.denimgroup.threadfix.webapp.controller;

import static com.denimgroup.threadfix.CollectionUtils.map;

import java.util.Map;

import com.denimgroup.threadfix.service.EmailListService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScheduledEmailReportService;
import com.denimgroup.threadfix.service.email.EmailConfiguration;
import com.fasterxml.jackson.annotation.JsonView;

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
	@JsonView(Object.class)
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
