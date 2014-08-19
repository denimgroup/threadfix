package com.denimgroup.threadfix.service.queue.scheduledjob;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.quartz.Job;
import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * Created by dzabdi88 on 8/15/14.
 */

public class ScheduledRemoteProviderImportJob implements Job {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledScanJob.class);

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        String jobName = context.getJobDetail().getFullName();
        log.info("ScheduledRemoteProviderImportJob " + jobName + " executing at " + new Date() + ". Sending request to queue.");

        JobDataMap dataMap = context.getJobDetail().getJobDataMap();
        String remoteProviderTypeIds = dataMap.getString("remoteProviderTypeIds");
        QueueSender queueSender = (QueueSender)dataMap.get("queueSender");

        List<String> remoteProviderTypeIdList = new ArrayList<>(Arrays.asList(remoteProviderTypeIds.split(",")));

        for(String remoteProviderTypeId : remoteProviderTypeIdList ) {
            queueSender.addRemoteProviderImport(Integer.parseInt(remoteProviderTypeId));
        }
    }
}
