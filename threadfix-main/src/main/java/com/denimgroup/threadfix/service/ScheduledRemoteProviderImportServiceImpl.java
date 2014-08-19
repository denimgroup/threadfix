package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.dao.ScheduledRemoteProviderImportDao;

import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderImport;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by dzabdi88 on 8/15/14.
 */

@Service
@Transactional(readOnly = false)
public class ScheduledRemoteProviderImportServiceImpl extends ScheduledJobServiceImpl<ScheduledRemoteProviderImport> implements ScheduledRemoteProviderImportService {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderImportServiceImpl.class);

    private ScheduledRemoteProviderImportDao scheduledRemoteProviderImportDao;

    @Autowired
    public ScheduledRemoteProviderImportServiceImpl(ScheduledRemoteProviderImportDao scheduledRemoteProviderImportDao) {
        this.scheduledRemoteProviderImportDao = scheduledRemoteProviderImportDao;
    }

    @Override
    protected ScheduledJobDao<ScheduledRemoteProviderImport> getScheduledJobDao() {
        return scheduledRemoteProviderImportDao;
    }
}
