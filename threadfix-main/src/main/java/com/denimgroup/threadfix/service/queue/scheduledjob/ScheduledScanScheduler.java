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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ScheduledScanService;
import com.denimgroup.threadfix.service.queue.QueueSender;
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
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 1/14/14
 * Time: 5:03 PM
 * To change this template use File | Settings | File Templates.
 */
@Component
public class ScheduledScanScheduler {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledScanScheduler.class);
    private static Scheduler scheduler = getScheduler();

    @Autowired(required = false)
    private ScheduledScanService scheduledScanService;

    @Autowired
    private QueueSender queueSender;

    public static Scheduler getScheduler() {
        if (scheduler == null) {
            SchedulerFactory schedulerFactory = new StdSchedulerFactory();
           try {
            scheduler = schedulerFactory.getScheduler();
           }   catch (SchedulerException ex) {
               log.error("Error when trying to get a reference to a scheduler", ex);
           }
        }
        return scheduler;
    }
    @PostConstruct
    public void run() {
        if (scheduler == null || scheduledScanService == null)
            return;

        log.info("Loading all Scheduled Scans from database");
        List<ScheduledScan> scheduledScans = scheduledScanService.loadAll();
        log.info("Got " + scheduledScans.size() + " Scheduled Scans");

        log.info("------- Scheduling Jobs ----------------");
        for (ScheduledScan scheduledScan: scheduledScans) {
            addScheduledScan(scheduledScan);
        }
        log.info("------- End Scheduling Jobs ----------------");

        try {
            scheduler.start();
        } catch (SchedulerException scheEx) {
            log.error("Error when starting Scheduler", scheEx);
        }
    }

    private String getCronExpression(ScheduledScan scheduledScan) {

        DayInWeek dayInWeek = DayInWeek.getDay(scheduledScan.getDay());
        ScheduledFrequencyType frequencyType = ScheduledFrequencyType.getFrequency(scheduledScan.getFrequency());
        ScheduledPeriodType scheduledPeriodType = ScheduledPeriodType.getPeriod(scheduledScan.getPeriod());
        String cronExpression = null;

        // Set DayOfWeek is ? if schedule daily, and MON-SUN otherwise
        String day = "?";
        if (frequencyType == ScheduledFrequencyType.WEEKLY) {
            if (dayInWeek == null) {
                log.warn("Unable to schedule ScheduledScanId " + scheduledScan.getId() + " " + scheduledScan.getFrequency() + " " + scheduledScan.getDay());
                return cronExpression;
            }
            day = dayInWeek.getDay();
        }

        // Set DayOfMonth is ? if schedule weekly, and * otherwise
        String dayOfMonth = (ScheduledFrequencyType.WEEKLY ==
                frequencyType ? "?" : "*");

        int hour = scheduledScan.getHour();
        if (ScheduledPeriodType.PM == scheduledPeriodType && hour < 12)
            hour += 12;

        cronExpression = "0 " + scheduledScan.getMinute() + " " + hour + " " + dayOfMonth + " * " + day;

        return cronExpression;
    }

    public boolean removeScheduledScan(ScheduledScan scheduledScan) {
        String groupName = createGroupName(scheduledScan);
        String jobName = createJobName(scheduledScan);
        try {
            scheduler.deleteJob(JobKey.jobKey(jobName, groupName));
            log.info(groupName + "." + jobName + " was successfully deleted from scheduler");
        } catch (SchedulerException e) {
            log.error("Error when deleting job from scheduler", e);
            return false;
        }
        return true;
    }

    public boolean addScheduledScan(ScheduledScan scheduledScan) {

        String groupName = createGroupName(scheduledScan);
        String jobName = createJobName(scheduledScan);

        JobDetail job = JobBuilder
                .newJob(ScheduledScanJob.class)
                .withIdentity(jobName, groupName).build();

        job.getJobDataMap().put("scheduledScanId", scheduledScan.getId());

        job.getJobDataMap().put("queueSender", queueSender);
        try {
            String cronExpression = getCronExpression(scheduledScan);
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

    private String createGroupName(ScheduledScan scheduledScan) {
        Application application = scheduledScan.getApplication();
        return application.getOrganization().getName() + "/" + application.getName();
    }

    private String createJobName(ScheduledScan scheduledScan) {
        return "ScheduledScanId_" + scheduledScan.getId() + "_" + scheduledScan.getScanner();
    }


}
