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
