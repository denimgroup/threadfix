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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.entities.DayInWeek;
import com.denimgroup.threadfix.data.entities.ScheduledFrequencyType;
import com.denimgroup.threadfix.data.entities.ScheduledJob;
import com.denimgroup.threadfix.data.entities.ScheduledPeriodType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.quartz.CronExpression;

import java.util.List;

/**
 * Created by zabdisubhan on 8/15/14.
 */

@Service
@Transactional(readOnly = false)
public abstract class ScheduledJobServiceImpl<S extends ScheduledJob> implements ScheduledJobService<S> {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledJobServiceImpl.class);

    protected abstract ScheduledJobDao<S> getScheduledJobDao();

    @Override
    public int save(S scheduledJob) {
        getScheduledJobDao().saveOrUpdate(scheduledJob);
        int scheduledJobId = scheduledJob.getId();

        log.info("Created or updated ScheduledJob with id: " + scheduledJobId);

        return scheduledJobId;
    }

    @Override
    public String delete(S scheduledJob) {
        log.info("Deleting scheduled job");

        getScheduledJobDao().delete(scheduledJob);
        return null;
    }

    @Override
    public List<S> loadAll() {
        return getScheduledJobDao().retrieveAllActive();
    }

    @Override
    public S loadById(int scheduledJobId) {
        return getScheduledJobDao().retrieveById(scheduledJobId);
    }

    @Override
    public void validateCronExpression(S scheduledJob, BindingResult result) {

        String cronExpression = scheduledJob.getCronExpression();

        if (cronExpression == null) {
            result.rejectValue("cronExpression", null, null, "Cron Expression cannot be null");
        } else if (!CronExpression.isValidExpression(cronExpression)) {
            result.rejectValue("cronExpression", null, null, "Cron expression is invalid.");
        }
    }

    @Override
    public void validateDate(S scheduledJob, BindingResult result) {

        int hour = scheduledJob.getHour();
        int minute = scheduledJob.getMinute();
        String period = scheduledJob.getPeriod();
        String day = scheduledJob.getDay();
        String frequency = scheduledJob.getFrequency();

        if (result.hasFieldErrors("hour") || hour<0 || hour>12) {
            result.rejectValue("dateError", null, null, "Input hour as a number from 0 to 12");

            return;
        }
        if (result.hasFieldErrors("minute") || minute<0 || minute>59) {
            result.rejectValue("dateError", null, null, "Input minute as a number from 0 to 59");
            return;
        }
        if (result.hasFieldErrors("period") || ScheduledPeriodType.getPeriod(period)==null) {
            result.rejectValue("dateError", null, null, "Select AM or PM");
            return;
        }

        if (ScheduledFrequencyType.getFrequency(frequency) == ScheduledFrequencyType.WEEKLY
                && DayInWeek.getDay(day)==null) {
            result.rejectValue("dateError", null, null, "Select day from list");
        }

        // Clean day if it is Daily schedule
        if (ScheduledFrequencyType.getFrequency(frequency) == ScheduledFrequencyType.DAILY) {
            scheduledJob.setDay(null);
        }
    }

    /*
     * this method should eventually be, but is not set abstract for the moment, because children classes (scheduleDefectTrackerUpdate,
     * scheduledGRCupdate...) were not updated to use the new abstraction AbstractScheduledJobScheduler so don't need this method yet,
     * and don't have it overridden in their service class
     * */
    public S getDefaultScheduledJob(){
        return null;
    };
}
