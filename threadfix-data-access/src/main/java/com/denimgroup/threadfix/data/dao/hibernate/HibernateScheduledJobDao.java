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

package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ScheduledJobDao;
import com.denimgroup.threadfix.data.entities.ScheduledJob;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by zabdisubhan on 8/15/14.
 */

@Repository
public abstract class HibernateScheduledJobDao<S extends ScheduledJob> extends AbstractObjectDao<S> implements ScheduledJobDao<S> {

    @Autowired
    public HibernateScheduledJobDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public void delete(S scheduledJob) {
        sessionFactory.getCurrentSession().delete(scheduledJob);
    }

    // TODO USE CRITERIA!!!
    @Override
    public boolean checkSameDate(S scheduledJob) {

        Query query = null;
        String queryStr;

        if (scheduledJob.getDay() != null){
            queryStr = "select count(*) from :class scheduledJob " +
                    "where scheduledJob.day=:day and scheduledJob.period=:period " +
                    "and scheduledJob.hour=:hour and scheduledJob.minute=:minute";

            query = sessionFactory.getCurrentSession().createQuery(queryStr);
            query.setString("day", scheduledJob.getDay());

        } else if (scheduledJob.getFrequency() != null) {
            queryStr = "select count(*) from :class scheduledJob " +
                    "where scheduledJob.frequency=:frequency and scheduledJob.period=:period " +
                    "and scheduledJob.hour=:hour and scheduledJob.minute=:minute";

            query = sessionFactory.getCurrentSession().createQuery(queryStr);
            query.setString("frequency", scheduledJob.getFrequency());
        }

        if (query != null) {
            query.setInteger("hour", scheduledJob.getHour());
            query.setInteger("minute", scheduledJob.getMinute());
            query.setString("period", scheduledJob.getPeriod());
            query.setString("class", getClass().getSimpleName());

            Long count = (Long)query.uniqueResult();

            return (count > 0);
        }  else {
            return false;
        }
    }
}
