package com.denimgroup.threadfix.service.queue.scheduledjob;

import static org.quartz.CronScheduleBuilder.cronSchedule;

import java.text.ParseException;
import java.util.Date;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.bouncycastle.util.Strings;
import org.quartz.CronTrigger;
import org.quartz.Job;
import org.quartz.JobBuilder;
import org.quartz.JobDetail;
import org.quartz.JobKey;
import org.quartz.Scheduler;
import org.quartz.SchedulerException;
import org.quartz.SchedulerFactory;
import org.quartz.Trigger;
import org.quartz.TriggerBuilder;
import org.quartz.impl.StdSchedulerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.denimgroup.threadfix.data.entities.DayInWeek;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.ScheduledFrequencyType;
import com.denimgroup.threadfix.data.entities.ScheduledJob;
import com.denimgroup.threadfix.data.entities.ScheduledPeriodType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.ScheduledJobService;
import com.denimgroup.threadfix.service.queue.QueueSender;

//This class is the abstracted version of the classes like ScheduledGRCToolUpdater (everything is always the same in these)
public abstract class AbstractScheduledJobScheduler<T extends ScheduledJob> {
    // T would be an entity like ScheduledGRCToolUpdate

    private static final SanitizedLogger log = new SanitizedLogger(AbstractScheduledJobScheduler.class);
    private static Scheduler scheduler = getScheduler();

    //abstract the same way as in AbstractObjectDao, accesses through getter getScheduledJobService()
    private ScheduledJobService<T> scheduledJobService;
    private Class<? extends Job> jobClass;
    private String jobNameBase;
    private String jobNaturalName;
    private String jobGroupName;

    @Autowired
    private QueueSender queueSender;

    @Autowired
    DefaultConfigService defaultConfigService;


    //extending class must implement its constructor and pass the scheduledJobService through super()
    public AbstractScheduledJobScheduler(ScheduledJobService<T> scheduledJobService, Class<? extends Job> jobClass,
              String jobNameBase, String jobNaturalName, String jobGroupName) {
        this.scheduledJobService = scheduledJobService;//to be autowired in extending class
        this.jobClass = jobClass;
        this.jobNameBase = jobNameBase;
        this.jobNaturalName = jobNaturalName;
        this.jobGroupName = jobGroupName;
    }

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

        if(scheduledJobService == null) {
            return;
        }

        if (scheduler == null) {
            throw new IllegalStateException("Scheduler is null");
        }

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        if (!getHasAddedScheduledJob(config)) {
            //Add default scheduled job
            T defaultScheduledJob = scheduledJobService.getDefaultScheduledJob(); //not static method anymore, returns null if not overridden in service
            if (defaultScheduledJob == null){
                log.info("No default sechduled Job for " + jobNaturalName + ". Skipping default setup");
                return;
            }

            if (scheduledJobService.save(defaultScheduledJob) < 0) {
                throw new IllegalStateException("Saving Default " + jobNaturalName + " failed.");
            } else {

                log.info("------- Scheduling Default Job: " + defaultScheduledJob.getScheduledDate() + " ----------------");
                addScheduledJob(defaultScheduledJob);
                log.info("------- End Scheduling Job ----------------");

                setHasAddedScheduledJob(config, true);
                defaultConfigService.saveConfiguration(config);
            }
        } else {
            log.info("Loading all " + jobNaturalName + "s from database");
            List<T> scheduledJobs = scheduledJobService.loadAll();
            log.info("Got " + scheduledJobs.size() + " " + jobNaturalName + "s");

            log.info("------- Scheduling Jobs ----------------");
            for (T scheduledJob : scheduledJobs) {
                addScheduledJob(scheduledJob);
            }
            log.info("------- End Scheduling Jobs ----------------");
        }

        try {
            scheduler.start();
        } catch (SchedulerException scheEx) {
            log.error("Error when starting Scheduler", scheEx);
        }
    }

    private String getCronExpression(T scheduledJob) {

        DayInWeek dayInWeek = DayInWeek.getDay(scheduledJob.getDay());
        ScheduledFrequencyType frequencyType = ScheduledFrequencyType.getFrequency(scheduledJob.getFrequency());
        ScheduledPeriodType scheduledPeriodType = ScheduledPeriodType.getPeriod(scheduledJob.getPeriod());
        String cronExpression = null;

        // Set DayOfWeek is ? if schedule daily, and MON-SUN otherwise
        String day = "?";
        if (frequencyType == ScheduledFrequencyType.WEEKLY) {
            if (dayInWeek == null) {
                log.warn("Unable to schedule ScheduledGRCToolUpdateId " + scheduledJob.getId() + " " + scheduledJob.getFrequency() + " " + scheduledJob.getDay());
                return cronExpression;
            }
            day = Strings.toUpperCase(dayInWeek.getDay());
        }

        // Set DayOfMonth is ? if schedule weekly, and * otherwise
        String dayOfMonth = (ScheduledFrequencyType.WEEKLY == frequencyType?"?":"*");

        int hour = scheduledJob.getHour();
        if (ScheduledPeriodType.PM == scheduledPeriodType && hour < 12)
            hour += 12;

        cronExpression = "0 " + scheduledJob.getMinute() + " " + hour + " " + dayOfMonth+ " * " + day;

        return cronExpression;
    }

    public boolean removeScheduledJob(T scheduledJob) {
        String groupName = jobGroupName;//groupName accessed from a field instead of a method
        String jobName = createJobName(scheduledJob);
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
    public boolean addScheduledJob(T scheduledJob) {

        String groupName = jobGroupName;
        String jobName = createJobName(scheduledJob);

        JobDetail job = JobBuilder
                .newJob(jobClass)
                .withIdentity(jobName, groupName).build();
        job.getJobDataMap().put("queueSender", queueSender);
        setAdditionalJobDataMap(job,scheduledJob);

        try {
            String cronExpression = getCronExpression(scheduledJob);
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

    private String createJobName(T scheduledJob) {
        return jobNameBase + scheduledJob.getId();
    }

    protected abstract Boolean getHasAddedScheduledJob(DefaultConfiguration config);
    // return config.getHasAdded...()

    protected abstract void setHasAddedScheduledJob(DefaultConfiguration config, Boolean bool);
    // config.setHasAdded...(bool);

    //Optionally extend this method to add attributes to the job data map
    protected void setAdditionalJobDataMap(JobDetail job, T scheduledJob){}
}
