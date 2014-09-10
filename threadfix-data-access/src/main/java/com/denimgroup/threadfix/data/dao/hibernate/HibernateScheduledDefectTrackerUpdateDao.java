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

import com.denimgroup.threadfix.data.dao.ScheduledDefectTrackerUpdateDao;
import com.denimgroup.threadfix.data.entities.ScheduledDefectTrackerUpdate;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by zabdisubhan on 8/27/14.
 */

@Repository
public class HibernateScheduledDefectTrackerUpdateDao extends HibernateScheduledJobDao<ScheduledDefectTrackerUpdate> implements ScheduledDefectTrackerUpdateDao {

    @Autowired
    public HibernateScheduledDefectTrackerUpdateDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<ScheduledDefectTrackerUpdate> getClassReference() {
        return ScheduledDefectTrackerUpdate.class;
    }

    @Override
    public boolean checkSameDate(ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate) {

        Query query = null;

        if (scheduledDefectTrackerUpdate.getDay() != null){
            query = sessionFactory.getCurrentSession().createQuery(
                    "select count(*) from ScheduledDefectTrackerUpdate scheduledImport " +
                            "where scheduledImport.day=:day and scheduledImport.period=:period " +
                            "and scheduledImport.hour=:hour and scheduledImport.minute=:minute");

            query.setString("day", scheduledDefectTrackerUpdate.getDay());

        } else if (scheduledDefectTrackerUpdate.getFrequency() != null) {
            query = sessionFactory.getCurrentSession().createQuery(
                    "select count(*) from ScheduledDefectTrackerUpdate scheduledImport " +
                            "where scheduledImport.frequency=:frequency and scheduledImport.period=:period " +
                            "and scheduledImport.hour=:hour and scheduledImport.minute=:minute");

            query.setString("frequency", scheduledDefectTrackerUpdate.getFrequency());

        }

        if(query != null) {
            query.setInteger("hour", scheduledDefectTrackerUpdate.getHour());
            query.setInteger("minute", scheduledDefectTrackerUpdate.getMinute());
            query.setString("period", scheduledDefectTrackerUpdate.getPeriod());

            Long count = (Long)query.uniqueResult();

            return (count > 0);

        }  else {
            return false;
        }
    }
}
