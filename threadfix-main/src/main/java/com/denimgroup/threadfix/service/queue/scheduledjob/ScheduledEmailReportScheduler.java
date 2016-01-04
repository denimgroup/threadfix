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
