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
import org.hibernate.classic.Session;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.hibernate.transform.Transformers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

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
                .createQuery("from Application app where app.active = true and app.organization.id in (:ids) order by app.name")
                .setParameterList("ids", authenticatedTeamIds)
                .list();
    }

    @Override
    @Transactional(readOnly = false) // used to be true
    public Application retrieveById(int id) {
        return (Application) getActiveAppCriteria().add(Restrictions.eq("id", id)).uniqueResult();
    }

    @Override
    public Application retrieveByName(String name, int teamId) {
        return (Application) getActiveAppCriteria().add(Restrictions.eq("name",name))
                .add(Restrictions.eq("organization.id", teamId))
                .uniqueResult();
    }

    @Override
    public List<Application> retrieveByUniqueId(String uniqueId, int teamId) {

        Criteria criteria = getActiveAppCriteria().add(Restrictions.eq("uniqueId",uniqueId));
        if (teamId != -1) {
            criteria.add(Restrictions.eq("organization.id", teamId));
        }
        return (List<Application>)criteria.list();
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
        List<Integer> tagIdList = list();
        List<Integer> vulnTagIdList = list();
        return getTopXVulnerableAppsFromList(numApps, teamIdList, applicationIdList, tagIdList, vulnTagIdList);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Integer> getTopXVulnerableAppsFromList(int numApps, List<Integer> teamIdList,
                                                       List<Integer> applicationIdList,
                                                       List<Integer> tagIdList,
                                                       List<Integer> vulnTagIdList) {
        Session session = sessionFactory.getCurrentSession();
        Criteria criteria = session.createCriteria(Application.class);
        criteria.createAlias("vulnerabilities", "vulnerability");
        criteria.add(Restrictions.eq("active", true));
        criteria.add(Restrictions.eq("vulnerability.active", true));
        criteria.add(Restrictions.eq("vulnerability.hidden", false));
        criteria.add(Restrictions.eq("vulnerability.isFalsePositive", false));

        if (vulnTagIdList.size() > 0) {
            criteria.createAlias("vulnerability.tags", "tags");
            criteria.add(Restrictions.in("tags.id", vulnTagIdList));
        }

        if (teamIdList.isEmpty() || applicationIdList.isEmpty()) {
            if (!applicationIdList.isEmpty()) {
                criteria.add(Restrictions.in("id", applicationIdList));
            }

            if (!teamIdList.isEmpty()) {
                criteria.add(Restrictions.in("organization.id", teamIdList));
            }
        } else {
            criteria.add(Restrictions.or(
                    Restrictions.in("id", applicationIdList),
                    Restrictions.in("organization.id", teamIdList)
            ));
        }
        if (!tagIdList.isEmpty()) {
            criteria.createAlias("tags", "tag");
            criteria.add(Restrictions.in("tag.id", tagIdList));
        }

        criteria.setProjection(Projections.projectionList()
                        .add(Projections.groupProperty("id"))
                        .add(Projections.alias(Projections.countDistinct("vulnerability.id"), "vulnCount"))
        );
        criteria.addOrder(Order.desc("vulnCount"));

        List<Integer> list = list();
        List results = criteria.setMaxResults(numApps).list();
        for (Object result : results) {
            Object[] resultArray = (Object[]) result;
            list.add((Integer) resultArray[0]);
        }

        if (list.isEmpty())
            list = Arrays.asList(-1);
        return list;
    }

    @Override
    public long getUnmappedFindingCount(Integer appId) {
        Long result = (Long) sessionFactory.getCurrentSession().createCriteria(Finding.class)
                .add(Restrictions.isNull("vulnerability"))
                .createAlias("scan", "scanAlias")
                .createAlias("scanAlias.application", "applicationAlias")
                .add(Restrictions.eq("applicationAlias.id", appId))
                .setProjection(Projections.rowCount())
                .uniqueResult();
        return result == null ? 0 : result;
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
        Long result = (Long) getActiveAppCriteria()
                .setProjection(Projections.rowCount())
                .uniqueResult();
        return result == null ? 0 : result;
    }

    @Override
    public List<Map<String, Object>> retrieveAppsInfoMap(List<Integer> applicationIdList, List<Integer> vulnTagIds) {

        Session session = sessionFactory.getCurrentSession();
        Criteria criteria = session.createCriteria(Application.class);

        criteria.createAlias("vulnerabilities", "vulnerability");
        criteria.createAlias("organization", "team");
        criteria.add(Restrictions.eq("active", true));
        criteria.add(Restrictions.eq("vulnerability.active", true));
        criteria.add(Restrictions.eq("vulnerability.isFalsePositive", false));
        criteria.createAlias("vulnerability.genericSeverity", "severity");

        if (applicationIdList.size() > 0) {
            criteria.add(Restrictions.in("id", applicationIdList));
        }

        if (vulnTagIds.size() > 0) {
            criteria.createAlias("vulnerability.tags", "tags");
            criteria.add(Restrictions.in("tags.id", vulnTagIds));
        }

        criteria.setProjection(Projections.projectionList()
                        .add(Projections.groupProperty("id"), "appId")
                        .add(Projections.groupProperty("name"), "appName")
                        .add(Projections.groupProperty("team.id"), "teamId")
                        .add(Projections.groupProperty("team.name"), "teamName")
                        .add(Projections.groupProperty("severity.intValue"), "severityIntValue")
                        .add(Projections.groupProperty("severity.name"), "severityNameValue")
                        .add(Projections.alias(Projections.countDistinct("vulnerability.id"), "vulnCount"))
        );
        criteria.addOrder(Order.desc("vulnCount"));
        criteria.setResultTransformer(Transformers.ALIAS_TO_ENTITY_MAP);

        List results = criteria.list();
        return results;
    }

    @Override
    public Long countApps(Integer teamId, String searchString) {

        return (Long) getSearchAppCriteria(teamId, searchString)
                .setProjection(Projections.rowCount())
                .uniqueResult();
    }

    @Override
    public List<Application> getSearchResults(Integer teamId, String searchString, int number, int page, Set<Integer> appIds, Set<Integer> teamIds) {

        Criteria criteria = getSearchAppCriteria(teamId, searchString);
        criteria.addOrder(Order.asc("name"));
        addFiltering(criteria, teamIds, appIds);
        return (List<Application>) criteria.setMaxResults(number)
                .setFirstResult((page - 1) * number)
                .list();
    }

    @Override
    public Long countApps(Integer orgId, String searchString, Set<Integer> appIds, Set<Integer> teamIds) {
        Criteria criteria = getSearchAppCriteria(orgId, searchString);
        addFiltering(criteria, teamIds, appIds);

        return (Long) criteria.setProjection(Projections.rowCount())
                .uniqueResult();
    }

    @Override
    public Long countVulns(Integer orgId, Set<Integer> appIds, Set<Integer> teamIds) {
        Criteria criteria = getSearchAppCriteria(orgId, null);
        addFiltering(criteria, teamIds, appIds);

        return (Long) criteria.setProjection(Projections.sum("totalVulnCount"))
                .uniqueResult();
    }

    private Criteria getSearchAppCriteria(Integer orgId, String searchString) {
        Criteria criteria = getActiveAppCriteria();

        criteria.createAlias("organization", "team");
        criteria.add(Restrictions.eq("team.id", orgId));
        if (searchString != null && !searchString.isEmpty()){
            criteria.add(Restrictions.like("name", "%" + searchString + "%"));
        }

        return criteria;
    }

    private void addFiltering(Criteria criteria, Set<Integer> teamIds, Set<Integer> appIds) {

        boolean useAppIds = appIds != null,
                useTeamIds = teamIds != null;

        if (teamIds != null && teamIds.isEmpty()) {
            teamIds = set(0);
        }

        if (appIds != null && appIds.isEmpty()) {
            appIds = set(0);
        }

        if (!useAppIds && !useTeamIds) {
            return ;
        }

        if (useAppIds && useTeamIds) {
            criteria
                    .add(Restrictions.eq("team.active", true))
                    .add(Restrictions.or(
                            Restrictions.in("id", appIds),
                            Restrictions.in("team.id", teamIds)
                    ));
        } else if (useAppIds) {
            criteria
                    .add(Restrictions.in("id", appIds));
        } else {
            criteria
                    .add(Restrictions.in("team.id", teamIds))
                    .add(Restrictions.eq("team.active", true));
        }

    }
}
