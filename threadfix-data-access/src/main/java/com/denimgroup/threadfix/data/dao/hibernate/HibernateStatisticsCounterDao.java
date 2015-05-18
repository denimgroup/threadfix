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
package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.StatisticsCounterDao;
import com.denimgroup.threadfix.data.entities.StatisticsCounter;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

import static org.hibernate.criterion.Projections.rowCount;
import static org.hibernate.criterion.Restrictions.eq;

/**
 * Created by mcollins on 5/13/15.
 */
@Repository
public class HibernateStatisticsCounterDao
    extends AbstractObjectDao<StatisticsCounter>
    implements StatisticsCounterDao
{

    @Autowired
    public HibernateStatisticsCounterDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<StatisticsCounter> getClassReference() {
        return StatisticsCounter.class;
    }

    @Override
    public Long getCountForSeverity(int scanId, int severity) {

        Object o = getSession().createCriteria(StatisticsCounter.class)
                .add(eq("scanId", scanId))
                .add(eq("currentGenericSeverityId", severity))
                .setProjection(rowCount())
                .uniqueResult();

        return (Long) o;
    }

    private static String selectStart = "(select count(*) from StatisticsCounter counter where counter.scanId = scan.id and counter.currentGenericSeverityId = ";
    private String vulnIds = ")";
    private String fromClause = "from Scan scan where scan.id = :scanId";

    @SuppressWarnings("unchecked")
    @Override
    public List<Map<String, Object>> getFindingSeverityMap() {

        String hql = "select new map (count(*) as total, counter.scanId as scanId, counter.currentGenericSeverityId as genericSeverityId) from StatisticsCounter counter group by counter.scanId, counter.currentGenericSeverityId";

//        String selectStart = "(select count(*) from StatisticsCounter counter where counter.scanId =  and counter.currentGenericSeverityId = ";
//        String vulnIds = ")";
//        String fromClause = "from StatisticsCounter outerCounter group by outerCounter.scanId";
//
//        Object idsMap = sessionFactory.getCurrentSession().createQuery(
//                "select new map( scan.id as id, " +
//                        selectStart + "1" + vulnIds + " as info, " +
//                        selectStart + "2" + vulnIds + " as low, " +
//                        selectStart + "3" + vulnIds + " as medium, " +
//                        selectStart + "4" + vulnIds + " as high, " +
//                        selectStart + "5" + vulnIds + " as critical) " +
//                        fromClause
//        ).list();

        Object idsMap = getSession().createQuery(hql).list();
        return (List<Map<String, Object>>) idsMap;
    }
}
