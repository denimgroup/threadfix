package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.ScheduledRemoteProviderImportDao;
import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderImport;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by zabdisubhan on 8/15/14.
 */

@Repository
public class HibernateScheduledRemoteProviderImportDao extends HibernateScheduledJobDao<ScheduledRemoteProviderImport> implements ScheduledRemoteProviderImportDao {

    @Autowired
    public HibernateScheduledRemoteProviderImportDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<ScheduledRemoteProviderImport> getClassReference() {
        return ScheduledRemoteProviderImport.class;
    }
}
