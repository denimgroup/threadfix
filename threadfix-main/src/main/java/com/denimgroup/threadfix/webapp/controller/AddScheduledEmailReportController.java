package com.denimgroup.threadfix.webapp.controller;

import javax.validation.Valid;

import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.views.AllViews;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.denimgroup.threadfix.data.entities.EmailList;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScheduledEmailReportService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledEmailReportScheduler;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Controller
@RequestMapping("/configuration/scheduledEmailReports/add")
public class AddScheduledEmailReportController {

	private final SanitizedLogger log = new SanitizedLogger(AddScheduledEmailReportController.class);

	@Autowired
	private ScheduledEmailReportService scheduledEmailReportService;
	@Autowired
	private ScheduledEmailReportScheduler scheduledEmailReportScheduler;
	@Autowired
	private OrganizationService organizationService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("day", "frequency", "hour", "minute", "period", "severityLevel.id", "severityLevel.name",
				"organizations*", "scheduleType", "cronExpression");
	}

	@RequestMapping(method = RequestMethod.POST)
	@JsonView(AllViews.ScheduledEmailReportView.class)
	public @ResponseBody RestResponse<ScheduledEmailReport> addScheduledEmailReport(
			@Valid @ModelAttribute ScheduledEmailReport scheduledEmailReport,
			BindingResult result) {

		log.info("Start adding scheduled Email Report.");

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_EMAIL_REPORTS, null, null)){
			return RestResponse.failure("You are not allowed to modify scheduled email reports.");
		}

		if (scheduledEmailReport.getScheduleType().equals("CRON")) {
            scheduledEmailReport.clearDate();
			scheduledEmailReportService.validateCronExpression(scheduledEmailReport, result);
			GenericSeverity severityLevel = scheduledEmailReport.getSeverityLevel();
			if(severityLevel != null){
				GenericSeverity dbGenericSeverity = genericSeverityService.loadById(severityLevel.getId());
				if (dbGenericSeverity!=null) {
					scheduledEmailReport.setSeverityLevel(dbGenericSeverity);
				}
			}
		} else if (scheduledEmailReport.getScheduleType().equals("SELECT")) {
            scheduledEmailReport.clearCronExpression();
			scheduledEmailReportService.validateDate(scheduledEmailReport, result);
			scheduledEmailReportService.validateScheduleEmailReport(scheduledEmailReport, result);
		}
		List<EmailList> emptyEmailLists = list();
		scheduledEmailReport.setEmailLists(emptyEmailLists);
		List<String> emptyEmailAddresses = list();
		scheduledEmailReport.setEmailAddresses(emptyEmailAddresses);

		if (result.hasErrors()) {
			return FormRestResponse.failure("Encountered errors.", result);
		}

		if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
			return RestResponse.failure("Adding Scheduled Email Report failed.");
		}

		String resultMessage = scheduledEmailReportService.addJobToScheduler(scheduledEmailReport);
		if (resultMessage==null){
			return RestResponse.success(scheduledEmailReport);
		}
		else {
			scheduledEmailReportService.delete(scheduledEmailReport);
			return RestResponse.failure(resultMessage);
		}
	}
}
