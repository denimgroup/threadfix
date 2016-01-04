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
import com.denimgroup.threadfix.service.ScheduledDefectTrackerUpdateService;
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
 * @author zabdisubhan
 *
 */

@Component
public class ScheduledDefectTrackerUpdater {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledDefectTrackerUpdater.class);
    private static Scheduler scheduler = getScheduler();

    @Autowired
    private ScheduledDefectTrackerUpdateService scheduledDefectTrackerUpdateService;

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
        if (scheduler == null) {
            throw new IllegalStateException("Scheduler is null");
        }

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        if (!config.getHasAddedScheduledDefectTrackerUpdates()) {
            //Add default scheduled defect tracker update
            ScheduledDefectTrackerUpdate defaultScheduledUpdate = ScheduledDefectTrackerUpdate.getDefaultScheduledUpdate();

            if (scheduledDefectTrackerUpdateService.save(defaultScheduledUpdate) < 0) {
                throw new IllegalStateException("Saving Default Scheduled Defect Tracker Update failed.");
            } else {

                log.info("------- Scheduling Default Job: "+defaultScheduledUpdate.getScheduledDate()+" ----------------");
                addScheduledDefectTrackerUpdate(defaultScheduledUpdate);
                log.info("------- End Scheduling Job ----------------");

                config.setHasAddedScheduledDefectTrackerUpdates(true);
                defaultConfigService.saveConfiguration(config);
            }
        } else {
            log.info("Loading all Scheduled Defect Tracker Updates from database");
            List<ScheduledDefectTrackerUpdate> scheduledDefectTrackerUpdates = scheduledDefectTrackerUpdateService.loadAll();
            log.info("Got " + scheduledDefectTrackerUpdates.size() + " Scheduled Defect Tracker Updates");

            log.info("------- Scheduling Jobs ----------------");
            for (ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate : scheduledDefectTrackerUpdates) {
                addScheduledDefectTrackerUpdate(scheduledDefectTrackerUpdate);
            }
            log.info("------- End Scheduling Jobs ----------------");
        }

        try {
            scheduler.start();
        } catch (SchedulerException scheEx) {
            log.error("Error when starting Scheduler", scheEx);
        }
    }

    private String getCronExpression(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate) {

        DayInWeek dayInWeek = DayInWeek.getDay(scheduledDefectTrackerUpdate.getDay());
        ScheduledFrequencyType frequencyType = ScheduledFrequencyType.getFrequency(scheduledDefectTrackerUpdate.getFrequency());
        ScheduledPeriodType scheduledPeriodType = ScheduledPeriodType.getPeriod(scheduledDefectTrackerUpdate.getPeriod());
        String cronExpression = null;

        // Set DayOfWeek is ? if schedule daily, and MON-SUN otherwise
        String day = "?";
        if (frequencyType == ScheduledFrequencyType.WEEKLY) {
            if (dayInWeek == null) {
                log.warn("Unable to schedule ScheduledDefectTrackerUpdateId " + scheduledDefectTrackerUpdate.getId() + " " + scheduledDefectTrackerUpdate.getFrequency() + " " + scheduledDefectTrackerUpdate.getDay());
                return cronExpression;
            }
            day = dayInWeek.getDay().toUpperCase();
        }

        // Set DayOfMonth is ? if schedule weekly, and * otherwise
        String dayOfMonth = (ScheduledFrequencyType.WEEKLY == frequencyType?"?":"*");

        int hour = scheduledDefectTrackerUpdate.getHour();
        if (ScheduledPeriodType.PM == scheduledPeriodType && hour < 12)
            hour += 12;

        cronExpression = "0 " + scheduledDefectTrackerUpdate.getMinute() + " " + hour + " " + dayOfMonth+ " * " + day;

        return cronExpression;
    }

    public boolean removeScheduledDefectTrackerUpdate(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate) {
        String groupName = createGroupName();
        String jobName = createJobName(scheduledDefectTrackerUpdate);
        try {
            scheduler.deleteJob(JobKey.jobKey(jobName, groupName));
            log.info(groupName + "." + jobName + " was successfully deleted from scheduler");
        } catch (SchedulerException e) {
            log.error("Error when deleting job from scheduler", e);
            return false;
        }
        return true;
    }

    // TODO abstract most of this out
    @SuppressWarnings("unchecked")
    public boolean addScheduledDefectTrackerUpdate(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate) {

        String groupName = createGroupName();
        String jobName = createJobName(scheduledDefectTrackerUpdate);

        JobDetail job = JobBuilder
                .newJob(ScheduledDefectTrackerUpdateJob.class)
                .withIdentity(jobName, groupName).build();
        job.getJobDataMap().put("queueSender", queueSender);

        try {
            String cronExpression = getCronExpression(scheduledDefectTrackerUpdate);
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
        return "DefectTrackers";
    }

    private String createJobName(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate) {
        return "ScheduledDefectTrackerUpdateId_" + scheduledDefectTrackerUpdate.getId();
    }
}
