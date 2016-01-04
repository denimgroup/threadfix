package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Organization;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;

public interface ScheduledEmailReportService extends ScheduledJobService<ScheduledEmailReport> {

	/**
	 * Validates and loads properly the valid relationships with db entities in the ScheduledEmailReport variable, but must not saves the variable for persistence.
	 * If errors are encountered, the errors are returns in the result variable
	 * @param scheduledEmailReport
	 * @param result
	 */
	void validateScheduleEmailReport(ScheduledEmailReport scheduledEmailReport, BindingResult result);

	String addJobToScheduler(ScheduledEmailReport newScheduledEmailReport);

	String removeJobFromScheduler(ScheduledEmailReport oldScheduledEmailReport);

	String replaceJobFromScheduler(ScheduledEmailReport oldScheduledEmailReport, ScheduledEmailReport newScheduledEmailReport);

	void removeTeam(ScheduledEmailReport scheduledEmailReport, Organization organization);
}
