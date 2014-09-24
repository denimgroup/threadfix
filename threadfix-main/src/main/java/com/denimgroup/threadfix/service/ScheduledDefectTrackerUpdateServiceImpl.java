////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.dao.ScheduledDefectTrackerUpdateDao;

import com.denimgroup.threadfix.data.entities.ScheduledDefectTrackerUpdate;
import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderImport;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

/**
 * Created by dzabdi88 on 8/27/14.
 */

@Service
@Transactional(readOnly = false)
public class ScheduledDefectTrackerUpdateServiceImpl extends ScheduledJobServiceImpl<ScheduledDefectTrackerUpdate> implements ScheduledDefectTrackerUpdateService {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledDefectTrackerUpdateServiceImpl.class);

    private ScheduledDefectTrackerUpdateDao scheduledDefectTrackerUpdateDao;

    @Autowired
    public ScheduledDefectTrackerUpdateServiceImpl(ScheduledDefectTrackerUpdateDao scheduledDefectTrackerUpdateDao) {
        this.scheduledDefectTrackerUpdateDao = scheduledDefectTrackerUpdateDao;
    }

    @Override
    protected ScheduledJobDao<ScheduledDefectTrackerUpdate> getScheduledJobDao() {
        return scheduledDefectTrackerUpdateDao;
    }

    @Override
    public void validateSameDate(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate, BindingResult result) {
        if (getScheduledJobDao().checkSameDate(scheduledDefectTrackerUpdate, "ScheduledDefectTrackerUpdate")) {
            result.rejectValue("dateError", null, null, "Another defect tracker update is scheduled at that time/frequency");
        }
    }
}
