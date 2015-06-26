package com.denimgroup.threadfix.service.queue.scheduledjob;

import java.util.Date;

import org.quartz.Job;
import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;

public class ScheduledEmailReportJob implements Job {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledEmailReportJob.class);

	@Override
	public void execute(JobExecutionContext context) throws JobExecutionException {
        String jobName = context.getJobDetail().getDescription();
        log.info("ScheduledEmailReportJob " + jobName + " executing at " + new Date() + ". Sending request to queue.");

        JobDataMap dataMap = context.getJobDetail().getJobDataMap();
        int scheduledEmailReportId = dataMap.getInt("scheduledEmailReportId");
        QueueSender queueSender = (QueueSender)dataMap.get("queueSender");
        queueSender.startEmailReport(scheduledEmailReportId);
    }
}
