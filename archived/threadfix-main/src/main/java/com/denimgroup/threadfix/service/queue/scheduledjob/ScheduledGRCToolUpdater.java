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
import com.denimgroup.threadfix.service.ScheduledGRCToolUpdateService;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.quartz.*;
import org.quartz.impl.StdSchedulerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import static org.quartz.CronScheduleBuilder.cronSchedule;

/**
 * Created by zabdisubhan on 8/27/14.
 */

@Component
public class ScheduledGRCToolUpdater {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledGRCToolUpdater.class);
    private static Scheduler scheduler = getScheduler();

    @Autowired(required=false)
    private ScheduledGRCToolUpdateService scheduledGRCToolUpdateService;

    @Autowired
    private QueueSender queueSender;

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

    @PreDestroy
    public void destroy() {
        if (scheduler != null) {
            log.info("Shutting down scheduler.");
            try {
                scheduler.shutdown();
                log.info("Successfully shut down scheduler.");
            } catch (SchedulerException e) {
                log.error("Received SchedulerException while shutting down the scheduler: ", e);
            }
        }
    }

    @PostConstruct
    public void run() {

        if(scheduledGRCToolUpdateService == null) {
            return;
        }

        if (scheduler == null) {
            throw new IllegalStateException("Scheduler is null");
        }

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        if (!config.getHasAddedScheduledGRCToolUpdates()) {
            //Add default scheduled GRC tool update
            ScheduledGRCToolUpdate defaultScheduledUpdate = ScheduledGRCToolUpdate.getDefaultScheduledUpdate();

            if (scheduledGRCToolUpdateService.save(defaultScheduledUpdate) < 0) {
                throw new IllegalStateException("Saving Default Scheduled GRC Tool Update failed.");
            } else {

                log.info("------- Scheduling Default Job: "+defaultScheduledUpdate.getScheduledDate()+" ----------------");
                addScheduledGRCToolUpdate(defaultScheduledUpdate);
                log.info("------- End Scheduling Job ----------------");

                config.setHasAddedScheduledGRCToolUpdates(true);
                defaultConfigService.saveConfiguration(config);
            }
        } else {
            log.info("Loading all Scheduled GRC Tool Updates from database");
            List<ScheduledGRCToolUpdate> scheduledGRCToolUpdates = scheduledGRCToolUpdateService.loadAll();
            log.info("Got " + scheduledGRCToolUpdates.size() + " Scheduled GRC Tool Updates");

            log.info("------- Scheduling Jobs ----------------");
            for (ScheduledGRCToolUpdate scheduledGRCToolUpdate : scheduledGRCToolUpdates) {
                addScheduledGRCToolUpdate(scheduledGRCToolUpdate);
            }
            log.info("------- End Scheduling Jobs ----------------");
        }

        try {
            scheduler.start();
        } catch (SchedulerException scheEx) {
            log.error("Error when starting Scheduler", scheEx);
        }
    }

    private String getCronExpression(ScheduledGRCToolUpdate scheduledGRCToolUpdate) {

        DayInWeek dayInWeek = DayInWeek.getDay(scheduledGRCToolUpdate.getDay());
        ScheduledFrequencyType frequencyType = ScheduledFrequencyType.getFrequency(scheduledGRCToolUpdate.getFrequency());
        ScheduledPeriodType scheduledPeriodType = ScheduledPeriodType.getPeriod(scheduledGRCToolUpdate.getPeriod());
        String cronExpression = null;

        // Set DayOfWeek is ? if schedule daily, and MON-SUN otherwise
        String day = "?";
        if (frequencyType == ScheduledFrequencyType.WEEKLY) {
            if (dayInWeek == null) {
                log.warn("Unable to schedule ScheduledGRCToolUpdateId " + scheduledGRCToolUpdate.getId() + " " + scheduledGRCToolUpdate.getFrequency() + " " + scheduledGRCToolUpdate.getDay());
                return cronExpression;
            }
        }

        // Set DayOfMonth is ? if schedule weekly, and * otherwise
        String dayOfMonth = (ScheduledFrequencyType.WEEKLY == frequencyType?"?":"*");

        int hour = scheduledGRCToolUpdate.getHour();
        if (ScheduledPeriodType.PM == scheduledPeriodType && hour < 12)
            hour += 12;

        cronExpression = "0 " + scheduledGRCToolUpdate.getMinute() + " " + hour + " " + dayOfMonth+ " * " + day;

        return cronExpression;
    }

    public boolean removeScheduledGRCToolUpdate(ScheduledGRCToolUpdate scheduledGRCToolUpdate) {
        String groupName = createGroupName();
        String jobName = createJobName(scheduledGRCToolUpdate);
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
    public boolean addScheduledGRCToolUpdate(ScheduledGRCToolUpdate scheduledGRCToolUpdate) {

        String groupName = createGroupName();
        String jobName = createJobName(scheduledGRCToolUpdate);

        JobDetail job = JobBuilder
                .newJob(ScheduledGRCToolUpdateJob.class)
                .withIdentity(jobName, groupName).build();
        job.getJobDataMap().put("queueSender", queueSender);

        try {
            String cronExpression = getCronExpression(scheduledGRCToolUpdate);
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
        return "GRCTools";
    }

    private String createJobName(ScheduledGRCToolUpdate scheduledGRCToolUpdate) {
        return "ScheduledGRCToolUpdateId_" + scheduledGRCToolUpdate.getId();
    }
}
