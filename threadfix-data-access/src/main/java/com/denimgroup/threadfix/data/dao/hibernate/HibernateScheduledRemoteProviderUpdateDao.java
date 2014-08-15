package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.ScheduledRemoteProviderUpdateDao;
import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderUpdate;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by zabdisubhan on 8/15/14.
 */

@Repository
public class HibernateScheduledRemoteProviderUpdateDao extends HibernateScheduledJobDao<ScheduledRemoteProviderUpdate> implements ScheduledRemoteProviderUpdateDao {

    @Autowired
    public HibernateScheduledRemoteProviderUpdateDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<ScheduledRemoteProviderUpdate> getClassReference() {
        return ScheduledRemoteProviderUpdate.class;
    }
}
