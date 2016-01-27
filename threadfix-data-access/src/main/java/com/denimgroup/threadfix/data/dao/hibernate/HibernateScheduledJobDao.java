////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.annotation.Nonnull;

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

    @Override
    public boolean checkSameDate(@Nonnull S scheduledJob) {
        if (scheduledJob.getDay() == null && scheduledJob.getFrequency() == null) {
            throw new IllegalArgumentException("Got scheduled job without day or frequency.");
        }

        Criteria criteria = getSession().createCriteria(getClassReference());

        if (scheduledJob.getDay() != null) {
            criteria.add(Restrictions.eq("day", scheduledJob.getDay()));
        } else if (scheduledJob.getFrequency() != null) {
            criteria.add(Restrictions.eq("frequency", scheduledJob.getFrequency()));
        }

        criteria.add(Restrictions.eq("hour",   scheduledJob.getHour()));
        criteria.add(Restrictions.eq("minute", scheduledJob.getMinute()));
        criteria.add(Restrictions.eq("period", scheduledJob.getPeriod()));
        criteria.setProjection(Projections.rowCount());

        Long count = (Long) criteria.uniqueResult();

        return (count > 0);
    }
}
