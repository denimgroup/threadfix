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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.ScheduledRemoteProviderImportService;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.apache.commons.beanutils.BeanToPropertyValueTransformer;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static org.quartz.CronScheduleBuilder.cronSchedule;

/**
 * Created by zabdisubhan on 8/14/14.
 */

@Component
public class ScheduledRemoteProviderImporter {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderImporter.class);
    private static Scheduler scheduler = getScheduler();

    @Autowired
    private ScheduledRemoteProviderImportService scheduledRemoteProviderImportService;

    @Autowired
    private QueueSender queueSender;

    @Autowired
    private RemoteProviderTypeService remoteProviderTypeService;

    @Autowired
    DefaultConfigService defaultConfigService;

    public static Scheduler getScheduler() {
        if (scheduler == null) {
            SchedulerFactory schedulerFactory = new StdSchedulerFactory();
            try {
                scheduler = schedulerFactory.getScheduler();
            } catch (SchedulerException ex) {
                log.error("Error when trying to get a reference to a scheduler", ex);
            }
        }
        return scheduler;
    }
    @PostConstruct
    public void run() {
        if (scheduler == null) {
            throw new IllegalStateException("Scheduler is null");
        }

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        if (!config.getHasAddedScheduledImports()) {
            //Add default scheduled import
            ScheduledRemoteProviderImport defaultScheduledImport = ScheduledRemoteProviderImport.getDefaultScheduledImport();

            if (scheduledRemoteProviderImportService.save(defaultScheduledImport) < 0) {
                throw new IllegalStateException("Saving Default Scheduled Remote Provider Import failed.");
            } else {

                log.info("------- Scheduling Default Job: "+defaultScheduledImport.getScheduledDate()+" ----------------");
                addScheduledRemoteProviderImport(defaultScheduledImport);
                log.info("------- End Scheduling Job ----------------");

                config.setHasAddedScheduledImports(true);
                defaultConfigService.saveConfiguration(config);
            }
        } else {
            log.info("Loading all Scheduled Imports from database");
            List<ScheduledRemoteProviderImport> scheduledRemoteProviderImports = scheduledRemoteProviderImportService.loadAll();
            log.info("Got " + scheduledRemoteProviderImports.size() + " Scheduled Remote Provider Imports");

            log.info("------- Scheduling Jobs ----------------");
            for (ScheduledRemoteProviderImport scheduledRemoteProviderImport : scheduledRemoteProviderImports) {
                addScheduledRemoteProviderImport(scheduledRemoteProviderImport);
            }
            log.info("------- End Scheduling Jobs ----------------");
        }

        try {
            scheduler.start();
        } catch (SchedulerException scheEx) {
            log.error("Error when starting Scheduler", scheEx);
        }
    }

    private String getCronExpression(ScheduledRemoteProviderImport scheduledRemoteProviderImport) {

        DayInWeek dayInWeek = DayInWeek.getDay(scheduledRemoteProviderImport.getDay());
        ScheduledFrequencyType frequencyType = ScheduledFrequencyType.getFrequency(scheduledRemoteProviderImport.getFrequency());
        ScheduledPeriodType scheduledPeriodType = ScheduledPeriodType.getPeriod(scheduledRemoteProviderImport.getPeriod());
        String cronExpression = null;

        // Set DayOfWeek is ? if schedule daily, and MON-SUN otherwise
        String day = "?";
        if (frequencyType == ScheduledFrequencyType.WEEKLY) {
            if (dayInWeek == null) {
                log.warn("Unable to schedule ScheduledRemoteProviderImportId " + scheduledRemoteProviderImport.getId() + " " + scheduledRemoteProviderImport.getFrequency() + " " + scheduledRemoteProviderImport.getDay());
                return cronExpression;
            }
            day = dayInWeek.getDay().toUpperCase();
        }

        // Set DayOfMonth is ? if schedule weekly, and * otherwise
        String dayOfMonth = (ScheduledFrequencyType.WEEKLY == frequencyType?"?":"*");

        int hour = scheduledRemoteProviderImport.getHour();
        if (ScheduledPeriodType.PM == scheduledPeriodType && hour < 12)
            hour += 12;

        cronExpression = "0 " + scheduledRemoteProviderImport.getMinute() + " " + hour + " " + dayOfMonth+ " * " + day;

        return cronExpression;
    }

    public boolean removeScheduledRemoteProviderImport(ScheduledRemoteProviderImport scheduledRemoteProviderImport) {
        String groupName = createGroupName();
        String jobName = createJobName(scheduledRemoteProviderImport);
        try {
            scheduler.deleteJob(JobKey.jobKey(jobName, groupName));
            log.info(groupName + "." + jobName + " was successfully deleted from scheduler");
        } catch (SchedulerException e) {
            log.error("Error when deleting job from scheduler", e);
            return false;
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    public boolean addScheduledRemoteProviderImport(ScheduledRemoteProviderImport scheduledRemoteProviderImport) {

        String groupName = createGroupName();
        String jobName = createJobName(scheduledRemoteProviderImport);

        JobDetail job = JobBuilder
                .newJob(ScheduledRemoteProviderImportJob.class)
                .withIdentity(jobName, groupName).build();
        List<RemoteProviderType> remoteProviderTypes = remoteProviderTypeService.loadAll();
        List<Integer> idList = (List<Integer>)CollectionUtils.collect(remoteProviderTypes, new BeanToPropertyValueTransformer("id"));
        String remoteProviderTypeIds = StringUtils.join(idList, ",");

        job.getJobDataMap().put("remoteProviderTypeIds", remoteProviderTypeIds);
        job.getJobDataMap().put("queueSender", queueSender);

        try {
            String cronExpression = getCronExpression(scheduledRemoteProviderImport);
            if (cronExpression == null)
                return false;

            Trigger trigger = TriggerBuilder.<CronTrigger>newTrigger()
                    .forJob(jobName, groupName)
                    .withIdentity(jobName, groupName)
                    .withSchedule(cronSchedule(cronExpression))
                    .build();

            Date ft = scheduler.scheduleJob(job, trigger);
            log.info(job.getKey() + " has been scheduled to run at: " + ft
                    + " and repeat based on expression: " + cronExpression);
        } catch (RuntimeException e) {
            if (e.getCause() instanceof ParseException) {
                log.error("Got ParseException while parsing cron expression.", e.getCause());
                return false;
            } else {
                throw e;
            }
        } catch (SchedulerException scheEx) {
            log.error("Error when scheduling job", scheEx);
            return false;
        }

        return true;
    }

    private String createGroupName() {
        return "RemoteProviders";
    }

    private String createJobName(ScheduledRemoteProviderImport scheduledRemoteProviderImport) {
        return "ScheduledRemoteProviderImportId_" + scheduledRemoteProviderImport.getId();
    }
}
