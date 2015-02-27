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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.hibernate.Criteria;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Hibernate Application DAO implementation. Most basic methods are implemented
 * in the AbstractGenericDao
 *
 * @author bbeverly
 */
@Repository
public class HibernateApplicationDao implements ApplicationDao {

    @Autowired
    private SessionFactory sessionFactory;

    @Override
    @SuppressWarnings("unchecked")
    public List<Application> retrieveAll() {
        return sessionFactory.getCurrentSession()
                .createQuery("from Application app order by app.name").list();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Application> retrieveAllActive() {
        return getActiveAppCriteria().addOrder(Order.asc("name")).list();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Application> retrieveAllActiveFilter(Set<Integer> authenticatedTeamIds) {
        return sessionFactory.getCurrentSession()
                .createQuery("from Application app where app.organization.id in (:ids) order by app.name")
                .setParameterList("ids", authenticatedTeamIds)
                .list();
    }

    @Override
    @Transactional(readOnly = false) // used to be true
    public Application retrieveById(int id) {
        return (Application) getActiveAppCriteria().add(Restrictions.eq("id",id)).uniqueResult();
    }

    @Override
    public Application retrieveByName(String name, int teamId) {
        return (Application) getActiveAppCriteria().add(Restrictions.eq("name",name))
                .add(Restrictions.eq("organization.id", teamId))
                .uniqueResult();
    }

    @Override
    public Application retrieveByUniqueId(String uniqueId, int teamId) {
        return (Application) getActiveAppCriteria().add(Restrictions.eq("uniqueId",uniqueId))
                .add(Restrictions.eq("organization.id", teamId))
                .uniqueResult();
    }

    private Criteria getActiveAppCriteria() {
        return sessionFactory.getCurrentSession()
                .createCriteria(Application.class)
                .add(Restrictions.eq("active", true));
    }

    @Override
    public void saveOrUpdate(Application application) {
        if (application != null && application.getId() != null) {
            sessionFactory.getCurrentSession().merge(application);
        } else {
            sessionFactory.getCurrentSession().saveOrUpdate(application);
        }
    }

    /**
     * This implementation is a little gross but way better than iterating through
     * all of the vulns on the TF side
     */
    @Override
    public List<Integer> loadVulnerabilityReport(Application application) {
        if (application == null) {
            assert false;
            return null;
        }

        List<Integer> ints = list();

        for (int i = 1; i < 6; i++) {
            long result = (Long) sessionFactory.getCurrentSession()
                    .createQuery("select count(*) from Vulnerability vuln " +
                            "where genericSeverity.intValue = :value " +
                            "and application = :app and active = true and hidden = false and isFalsePositive = false")
                    .setInteger("value", i)
                    .setInteger("app", application.getId())
                    .uniqueResult();

            ints.add((int) result);
        }

        long result = (Long) sessionFactory.getCurrentSession()
                .createQuery("select count(*) from Vulnerability vuln " +
                        "where application = :app and active = true and hidden = false and isFalsePositive = false")
                .setInteger("app", application.getId())
                .uniqueResult();
        ints.add((int) result);
        return ints;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<String> getTeamNames(List<Integer> appIds) {
        return (List<String>) sessionFactory.getCurrentSession()
                .createQuery("select distinct organization.name from Application application " +
                        "where id in (:idList)")
                .setParameterList("idList", appIds).list();
    }

    @SuppressWarnings("unchecked")
    public List<Vulnerability> getVulns(Application app) {
        return (List<Vulnerability>) sessionFactory.getCurrentSession()
                .createQuery("from Vulnerability vuln where vuln.application = :appId")
                .setInteger("appId", app.getId()).list();
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Integer> getTopXVulnerableAppsFromList(int numApps, List<Integer> teamIdList,
                                                       List<Integer> applicationIdList) {
        StringBuilder builder = new StringBuilder();
        builder.append("SELECT application.id as id " +
                " FROM Application as application join application.vulnerabilities as vulnerability " +
                " WHERE" +
                "   application.active = true AND " +
                " 	vulnerability.active = true AND " +
                "   vulnerability.isFalsePositive = false " );

        if (teamIdList.isEmpty() || applicationIdList.isEmpty()) {
            if (!applicationIdList.isEmpty()) {
                builder.append(" AND application.id IN (:applicationIdList)");
            }

            if (!teamIdList.isEmpty()) {
                builder.append(" AND application.organization.id IN (:teamIdList)");
            }
        } else {
            builder.append(" AND (application.id IN (:applicationIdList) OR application.organization.id IN (:teamIdList))");
        }

        builder.append(" GROUP BY application.id" +
                " ORDER BY count(vulnerability) desc");

        Query query = sessionFactory.getCurrentSession()
                .createQuery(builder.toString());
        if (!teamIdList.isEmpty())
            query.setParameterList("teamIdList", teamIdList);

        if (!applicationIdList.isEmpty()) {
            query.setParameterList("applicationIdList", applicationIdList);
        }
        List<Integer> list = query.setMaxResults(numApps)
                .list();

        if (list==null || list.isEmpty())
            list = Arrays.asList(new Integer[]{-1});
        return list;
    }

    @Override
    public long getUnmappedFindingCount(Integer appId) {
        return (long) sessionFactory.getCurrentSession().createCriteria(Finding.class)
                .add(Restrictions.isNull("vulnerability"))
                .createAlias("scan", "scanAlias")
                .createAlias("scanAlias.application", "applicationAlias")
                .add(Restrictions.eq("applicationAlias.id", appId))
                .setProjection(Projections.rowCount())
                .uniqueResult();
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Application> getTopAppsFromList(List<Integer> applicationIdList) {
        List<Application> apps = sessionFactory.getCurrentSession()
                .createQuery("SELECT application " +
                        " FROM Application as application " +
                        " WHERE application.id IN (:applicationIdList) AND " +
                        "   application.active = true " +
                        "ORDER BY application.totalVulnCount desc")
                .setParameterList("applicationIdList", applicationIdList)
                .list();
        if (apps == null)
            apps = list();
        return apps;
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<Object[]> getPointInTime(List<Integer> applicationIdList) {
        return sessionFactory
                .getCurrentSession()
                .createQuery(
                        "select sum(application.infoVulnCount) as infoCount, " +
                                "sum(application.lowVulnCount) as lowCount, " +
                                "sum(application.mediumVulnCount) as mediumCount, " +
                                "sum(application.highVulnCount) as highCount, " +
                                "sum(application.criticalVulnCount) as criticalCount, " +
                                "sum(application.totalVulnCount) as totalCount " +
                                "from Application as application " +
                                "where application.id in (:appIds) " +
                                "and application.active = true")
                .setParameterList("appIds", applicationIdList)
                .list();
    }

    @Override
    public long getApplicationCount() {
        return (long) getActiveAppCriteria().setProjection(Projections.rowCount()).uniqueResult();
    }
}
