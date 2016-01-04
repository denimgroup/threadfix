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
import com.denimgroup.threadfix.service.ScheduledDefectTrackerUpdateService;
import org.quartz.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author zabdisubhan
 *
 */

@Component
public class ScheduledDefectTrackerUpdater extends AbstractScheduledJobScheduler<ScheduledDefectTrackerUpdate> {

    private static final SanitizedLogger log = new SanitizedLogger(ScheduledDefectTrackerUpdater.class);

    @Autowired
    public ScheduledDefectTrackerUpdater(ScheduledDefectTrackerUpdateService scheduledDefectTrackerUpdateService){
        super(	scheduledDefectTrackerUpdateService,
                ScheduledDefectTrackerUpdateJob.class,
                "ScheduledDefectTrackerUpdateId_",
                "Scheduled Defect Tracker Update",
                "DefectTrackers");
    }

    @Override
    protected Boolean getHasAddedScheduledJob(DefaultConfiguration config) {
        return config.getHasAddedScheduledDefectTrackerUpdates();
    }

    @Override
    protected void setHasAddedScheduledJob(DefaultConfiguration config,	Boolean bool) {
        config.setHasAddedScheduledDefectTrackerUpdates(bool);
    }

    @Override
    protected void setAdditionalJobDataMap(JobDetail job, ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate){
        job.getJobDataMap().put("scheduledDefectTrackerUpdateId", scheduledDefectTrackerUpdate.getId());
    }

}
