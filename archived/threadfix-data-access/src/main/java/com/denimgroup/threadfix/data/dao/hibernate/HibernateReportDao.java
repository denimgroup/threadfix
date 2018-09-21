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

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ReportDao;
import com.denimgroup.threadfix.data.entities.Report;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author zabdisubhan
 */

@Repository
public class HibernateReportDao
        extends AbstractObjectDao<Report>
        implements ReportDao {

    @Autowired
    public HibernateReportDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Report retrieveByName(String name) {
        return (Report) sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("displayName", name))
                .uniqueResult();
    }

    @Override
    public Report retrieveByNameIgnoreCase(String name) {
        return (Report) sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("displayName", name).ignoreCase())
                .uniqueResult();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Report> retrieveAllAvailable() {
        return (List<Report>) getAvailableCriteria().list();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Report> retrieveAllNativeReports() {
        return (List<Report>) sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("nativeReport", true))
                .list();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Report> retrieveAllNonNativeReports() {
        return (List<Report>) sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("nativeReport", false))
                .list();
    }

    private Criteria getAvailableCriteria() {
        return sessionFactory.getCurrentSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("available", true));
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Report> retrieveByIds(List<Integer> reportIds) {
        return (List<Report>) getAvailableCriteria()
                .add(Restrictions.in("id", reportIds))
                .list();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Report> retrieveReportsByLocation(ReportLocation location) {
        return (List<Report>) getAvailableCriteria()
                .add(Restrictions.eq("location", location))
                .list();
    }

    @Override
    public void delete(Report report) {
        sessionFactory.getCurrentSession().delete(report);
    }

    // This HQL is relatively simple and probably more memory-efficient than pulling objects into memory
    @Override
    public void delete(Integer reportId) {
        Session session = sessionFactory.getCurrentSession();

        String hql;

        hql = "delete from Report where id = :id";
        session.createQuery(hql).setInteger("id", reportId).executeUpdate();
    }

    @Override
    public List<Report> retrieveAllNonNativeReportsByLocationType(ReportLocation location) {
        return (List<Report>) getAvailableCriteria()
                .add(Restrictions.eq("location", location))
                .add(Restrictions.eq("nativeReport", false))
                .list();
    }

    @Override
    protected Class<Report> getClassReference() {
        return Report.class;
    }
}
