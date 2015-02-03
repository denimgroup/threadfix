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
import com.denimgroup.threadfix.data.dao.DashboardWidgetDao;
import com.denimgroup.threadfix.data.entities.DashboardWidget;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.classic.Session;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author zabdisubhan
 */

@Repository
public class HibernateDashboardWidgetDao
        extends AbstractObjectDao<DashboardWidget>
        implements DashboardWidgetDao {

    @Autowired
    public HibernateDashboardWidgetDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public DashboardWidget retrieveByName(String name) {
        return (DashboardWidget) sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("displayName", name))
                .uniqueResult();
    }

    @Override
    public List<DashboardWidget> retrieveAllAvailable() {
        return (List<DashboardWidget>) getAvailableCriteria().list();
    }

    private Criteria getAvailableCriteria() {
        return sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("available", true));
    }

    @Override
    public List<DashboardWidget> retrieveByIds(List<Integer> dashboardWidgetIds) {

        return (List<DashboardWidget>) getAvailableCriteria()
                .add(Restrictions.in("id", dashboardWidgetIds))
                .list();

    }

    @Override
    public void delete(DashboardWidget dashboardWidget) {
        sessionFactory.getCurrentSession().delete(dashboardWidget);
    }

    // This HQL is relatively simple and probably more memory-efficient than pulling objects into memory
    @Override
    public void delete(Integer dashboardWidgetId) {
        Session session = sessionFactory.getCurrentSession();

        String hql;

        hql = "delete from DashboardWidget where id = :id";
        session.createQuery(hql).setInteger("id", dashboardWidgetId).executeUpdate();
    }

    @Override
    protected Class<DashboardWidget> getClassReference() {
        return DashboardWidget.class;
    }
}
