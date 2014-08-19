package com.denimgroup.threadfix.service.queue.scheduledjob;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.ScheduledRemoteProviderImportService;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.apache.commons.beanutils.BeanToPropertyValueTransformer;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.Strings;
import org.quartz.impl.StdSchedulerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.quartz.JobDetail;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SchedulerFactory;
import org.quartz.CronTrigger;

import javax.annotation.PostConstruct;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

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
        if (scheduler == null)
            return;

        log.info("Loading all Scheduled Scans from database");
        List<ScheduledRemoteProviderImport> scheduledRemoteProviderImports = scheduledRemoteProviderImportService.loadAll();
        log.info("Got " + scheduledRemoteProviderImports.size() + " Scheduled Remote Provider Imports");

        log.info("------- Scheduling Jobs ----------------");
        for (ScheduledRemoteProviderImport scheduledRemoteProviderImport : scheduledRemoteProviderImports) {
            addScheduledRemoteProviderImport(scheduledRemoteProviderImport);
        }
        log.info("------- End Scheduling Jobs ----------------");

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
            day = Strings.toUpperCase(dayInWeek.getDay());
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
            scheduler.deleteJob(jobName, groupName);
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

        JobDetail job = new JobDetail(jobName, groupName, ScheduledRemoteProviderImportJob.class);

        List<RemoteProviderType> remoteProviderTypes = remoteProviderTypeService.loadAll();
        List<Integer> idList = (List<Integer>)CollectionUtils.collect(remoteProviderTypes, new BeanToPropertyValueTransformer("id"));
        String remoteProviderTypeIds = StringUtils.join(idList, ",");

        job.getJobDataMap().put("remoteProviderTypeIds", remoteProviderTypeIds);
        job.getJobDataMap().put("queueSender", queueSender);

        try {
            String cronExpression = getCronExpression(scheduledRemoteProviderImport);
            if (cronExpression == null)
                return false;

            CronTrigger trigger = new CronTrigger(jobName, groupName, jobName, groupName, cronExpression);

            scheduler.addJob(job, true);
            Date ft = scheduler.scheduleJob(trigger);
            log.info(job.getKey() + " has been scheduled to run at: " + ft
                    + " and repeat based on expression: " + trigger.getCronExpression());
        } catch (ParseException ex) {
            log.error("Error when parsing trigger", ex);
            return false;
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
