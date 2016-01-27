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

import com.denimgroup.threadfix.data.entities.EmailList;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.EmailListService;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScheduledEmailReportService;
import com.denimgroup.threadfix.service.email.EmailFilterService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledEmailReportScheduler;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

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
	@Autowired
	private EmailFilterService emailFilterService;
	@Autowired
	private EmailListService emailListService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("day", "frequency", "hour", "minute", "period", "severityLevel.id", "severityLevel.name",
				"organizations*", "scheduleType", "cronExpression", "id");
	}

	@RequestMapping(value = "/update", method = RequestMethod.POST)
	@JsonView(AllViews.ScheduledEmailReportView.class)
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
	@JsonView(AllViews.ScheduledEmailReportView.class)
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
	@JsonView(AllViews.ScheduledEmailReportView.class)
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
		if (!emailFilterService.validateEmailAddress(emailAddress)){
			return RestResponse.failure("Email doesn't comply with filter");
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
	@JsonView(AllViews.ScheduledEmailReportView.class)
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

	@RequestMapping(value = "/addEmailList", method = RequestMethod.POST)
	@JsonView(AllViews.ScheduledEmailReportView.class)
	public @ResponseBody RestResponse<EmailList> addEmailList(
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId,
			@RequestParam("emailListId") Integer emailListId) {

		ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
		if (scheduledEmailReport == null) {
			return RestResponse.failure("Invalid email report.");
		}

        EmailList emailList = emailListService.loadById(emailListId);
		List<EmailList> emailLists = scheduledEmailReport.getEmailLists();

        if (emailLists.contains(emailList)){
			return RestResponse.failure("Email list already added.");
		} else {
			emailLists.add(emailList);
			scheduledEmailReport.setEmailLists(emailLists);
			if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
				return RestResponse.failure("Updating Scheduled Email Report failed.");
			}
			else {
				return RestResponse.success(emailList);
			}
		}
	}

	@RequestMapping(value = "/deleteEmailList", method = RequestMethod.POST)
	@JsonView(AllViews.ScheduledEmailReportView.class)
	public @ResponseBody RestResponse<EmailList> deleteEmailList(
			@PathVariable("scheduledEmailReportId") int scheduledEmailReportId,
            @RequestParam("emailListId") Integer emailListId) {

        ScheduledEmailReport scheduledEmailReport = scheduledEmailReportService.loadById(scheduledEmailReportId);
        if (scheduledEmailReport == null) {
            return RestResponse.failure("Invalid email report.");
        }

        EmailList emailList = emailListService.loadById(emailListId);
        List<EmailList> emailLists = scheduledEmailReport.getEmailLists();

        if (emailLists.contains(emailList)){
            emailLists.remove(emailList);
			scheduledEmailReport.setEmailLists(emailLists);
			if (scheduledEmailReportService.save(scheduledEmailReport) < 0) {
				return RestResponse.failure("Updating Scheduled Email Report failed.");
			}
			else {
				return RestResponse.success(emailList);
			}
		}
		else {
			return RestResponse.failure("Invalid Email List.");
		}
	}
}
