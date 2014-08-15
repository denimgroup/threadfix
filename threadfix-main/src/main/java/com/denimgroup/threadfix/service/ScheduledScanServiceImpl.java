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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.dao.ScheduledScanDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ScheduledScan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = false)
public class ScheduledScanServiceImpl extends ScheduledJobServiceImpl<ScheduledScan> implements ScheduledScanService {

	private final SanitizedLogger log = new SanitizedLogger(ScheduledScanServiceImpl.class);

	private ApplicationDao applicationDao;
    private ScheduledScanDao scheduledScanDao;

	@Autowired
	public ScheduledScanServiceImpl(ApplicationDao applicationDao,
                                    ScheduledScanDao scheduledScanDao) {
        this.applicationDao = applicationDao;
        this.scheduledScanDao = scheduledScanDao;
	}

    @Override
    protected ScheduledJobDao<ScheduledScan> getScheduledJobDao() {
        return scheduledScanDao;
    }

    @Override
    public int save(int appId, ScheduledScan scheduledScan) {
        int scheduledScanId = -1;

        Application application = applicationDao.retrieveById(appId);
        if(application != null) {
            scheduledScan.setApplication(application);
            scheduledScanDao.saveOrUpdate(scheduledScan);
            scheduledScanId = scheduledScan.getId();
            log.info("Created ScheduledScan with id: " + scheduledScanId);
        } else {
            log.warn("Invalid applicationId of " + appId + " provided. No scan scheduled");
        }

        return scheduledScanId;
    }

    @Override
    public String delete(ScheduledScan scheduledScan) {
        log.info("Deleting scheduled Scan " + scheduledScan.getScanner() + " of application with id "
                + scheduledScan.getApplication().getId());

        Application application = applicationDao.retrieveById(scheduledScan.getApplication().getId());

        if (application == null) {
            return "ScheduledScan couldn't be deleted. Unable to find application for this task.";
        }

        application.getScheduledScans().remove(scheduledScan);
        scheduledScan.setApplication(null);
        scheduledScanDao.delete(scheduledScan);
        applicationDao.saveOrUpdate(application);
        return null;
    }
}
