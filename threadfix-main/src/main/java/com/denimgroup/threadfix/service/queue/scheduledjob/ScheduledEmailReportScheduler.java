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

package com.denimgroup.threadfix.service.queue.scheduledjob;

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.service.ScheduledEmailReportService;
import org.quartz.JobDetail;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

@Component
@DependsOn("scheduledEmailReportService")
public class ScheduledEmailReportScheduler extends AbstractScheduledJobScheduler<ScheduledEmailReport> {

	@Autowired
	public ScheduledEmailReportScheduler(ScheduledEmailReportService scheduledEmailReportService){
		super(	scheduledEmailReportService,
				ScheduledEmailReportJob.class,
				"ScheduledEmailReportId_",
				"Scheduled Email Report",
				"EmailReports");
	}

	@Override
	protected Boolean getHasAddedScheduledJob(DefaultConfiguration config) {
		//we don't need to bother with config as we don't have any default for Email Reports
		return true;
	}

	@Override
	protected void setHasAddedScheduledJob(DefaultConfiguration config,	Boolean bool) {
		//we don't need to bother with config as we don't have any default for Email Reports
	}

	@Override
	protected void setAdditionalJobDataMap(JobDetail job, ScheduledEmailReport scheduledEmailReport){
		job.getJobDataMap().put("scheduledEmailReportId", scheduledEmailReport.getId());
	}
}
