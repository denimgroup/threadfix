////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.quartz.Job;
import org.quartz.JobDataMap;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;

import java.util.Date;

/**
 * Created by dzabdi88 on 8/15/14.
 */

public class ScheduledRemoteProviderImportJob implements Job {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderImportJob.class);

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        String jobName = context.getJobDetail().getDescription();
        log.info("ScheduledRemoteProviderImportJob " + jobName + " executing at " + new Date() + ". Sending request to queue.");

        JobDataMap dataMap = context.getJobDetail().getJobDataMap();
        String remoteProviderTypeIds = dataMap.getString("remoteProviderTypeIds");
        QueueSender queueSender = (QueueSender)dataMap.get("queueSender");

        for (String remoteProviderTypeId : remoteProviderTypeIds.split(",")) {

            if (remoteProviderTypeId == null || "".equals(remoteProviderTypeId.trim())) {
                log.error("Got empty string in remote provider update job.");
            } else if (remoteProviderTypeId.matches("^[0-9]+$")) {
                queueSender.addRemoteProviderImport(Integer.parseInt(remoteProviderTypeId));
            } else {
                log.error("Non-numeric String encountered for ID: " + remoteProviderTypeId);
            }
        }
    }
}
