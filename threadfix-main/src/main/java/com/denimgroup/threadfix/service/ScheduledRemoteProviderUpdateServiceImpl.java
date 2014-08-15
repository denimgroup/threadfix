package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.dao.ScheduledRemoteProviderUpdateDao;

import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderUpdate;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Created by dzabdi88 on 8/15/14.
 */

@Service
@Transactional(readOnly = false)
public class ScheduledRemoteProviderUpdateServiceImpl extends ScheduledJobServiceImpl<ScheduledRemoteProviderUpdate> implements ScheduledRemoteProviderUpdateService {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderUpdateServiceImpl.class);

    private ScheduledRemoteProviderUpdateDao scheduledRemoteProviderUpdateDao;

    @Autowired
    public ScheduledRemoteProviderUpdateServiceImpl(ScheduledRemoteProviderUpdateDao scheduledRemoteProviderUpdateDao) {
        this.scheduledRemoteProviderUpdateDao = scheduledRemoteProviderUpdateDao;
    }

    @Override
    protected ScheduledJobDao<ScheduledRemoteProviderUpdate> getScheduledJobDao() {
        return scheduledRemoteProviderUpdateDao;
    }
}
