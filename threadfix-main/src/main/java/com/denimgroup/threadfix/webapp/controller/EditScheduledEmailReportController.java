package com.denimgroup.threadfix.webapp.controller;

import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
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

@Controller
@RequestMapping("/configuration/scheduledEmailReports/{scheduledEmailReportId}")
public class EditScheduledEmailReportController {

	private final SanitizedLogger log = new SanitizedLogger(EditScheduledEmailReportController.class);

	@Autowired
	private ScheduledEmailReportService scheduledEmailReportService;
	@Autowired
	private ScheduledEmailReportScheduler scheduledEmailReportScheduler;
	@Autowired
	private OrganizationService organizationService;

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("id", "day", "frequency", "hour", "minute", "period", "severityLevel.id", "organizations*");
	}

	@RequestMapping(value = "/update", method = RequestMethod.POST)
	@JsonView(Object.class)
	public @ResponseBody RestResponse<ScheduledEmailReport> addScheduledEmailReport(
			@Valid @ModelAttribute ScheduledEmailReport scheduledEmailReport,
			BindingResult result,
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId) {

		log.info("Start updating scheduled Email Report.");
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_EMAIL_REPORTS, null, null)){
			return RestResponse.failure("You are not allowed to modify scheduled email reports.");
		}

		ScheduledEmailReport dbScheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
		if (dbScheduledEmailReport == null || !dbScheduledEmailReport.isActive()){
			return FormRestResponse.failure("Invalid update url");
		}

		scheduledEmailReportService.validateDate(scheduledEmailReport, result);
		scheduledEmailReportService.validateScheduleEmailReport(scheduledEmailReport, result);
		scheduledEmailReport.setEmailAddresses(dbScheduledEmailReport.getEmailAddresses());//don't know how to make it stick only with allowed fields

		if (result.hasErrors()) {
			return FormRestResponse.failure("Encountered errors.", result);
		}

		if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
			return RestResponse.failure("Updating Scheduled Email Report failed.");
		}

		String resultMessage = scheduledEmailReportService.replaceJobFromScheduler(dbScheduledEmailReport, scheduledEmailReport);
		if (resultMessage==null){
			return RestResponse.success(scheduledEmailReport);
		}
		else {
			scheduledEmailReportService.delete(scheduledEmailReport);
			return RestResponse.failure(resultMessage);
		}
	}

	@RequestMapping(value = "/delete", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> delete(
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId) {

		log.info("Start deleting scheduled email report");
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_EMAIL_REPORTS, null, null)){
			return RestResponse.failure("You are not authorized to delete this scheduled email report.");
		}

		ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
		if (scheduledEmailReport == null) {
			return RestResponse.failure("That scheduled email report was not found.");
		}

		String resultMessage = scheduledEmailReportService.removeJobFromScheduler(scheduledEmailReport);
		if (resultMessage==null){
			scheduledEmailReportService.delete(scheduledEmailReport);
			return RestResponse.success(scheduledEmailReport.getFrequency() + " Scheduled Email Report successfully deleted.");
		}
		else {
			return RestResponse.failure(resultMessage);
		}
	}

	@RequestMapping(value = "/addEmail", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> addEmailAddress(
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId,
			@RequestParam("emailAddress") String emailAddress) {

		ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
		if (scheduledEmailReport == null) {
			return RestResponse.failure("Invalid email report.");
		}
		List<String> emailAddresses = scheduledEmailReport.getEmailAddresses();
		if (emailAddresses.contains(emailAddress)){
			return RestResponse.failure("Email address already exists.");
		}
		else {
			emailAddresses.add(emailAddress);
			scheduledEmailReport.setEmailAddresses(emailAddresses);
			if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
				return RestResponse.failure("Updating Scheduled Email Report failed.");
			}
			else {
				return RestResponse.success(emailAddress);
			}
		}
	}

	@RequestMapping(value = "/deleteEmail", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> deleteEmailAddress(
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId,
			@RequestParam("emailAddress") String emailAddress) {

		ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
		if (scheduledEmailReport == null) {
			return RestResponse.failure("Invalid email report.");
		}
		List<String> emailAddresses = scheduledEmailReport.getEmailAddresses();
		if (emailAddresses.contains(emailAddress)){
			emailAddresses.remove(emailAddress);
			scheduledEmailReport.setEmailAddresses(emailAddresses);
			if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
				return RestResponse.failure("Updating Scheduled Email Report failed.");
			}
			else {
				return RestResponse.success(emailAddress);
			}
		}
		else {
			return RestResponse.failure("Invalid Email address.");
		}
	}
}
