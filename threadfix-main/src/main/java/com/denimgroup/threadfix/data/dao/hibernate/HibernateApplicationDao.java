////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * Hibernate Application DAO implementation. Most basic methods are implemented
 * in the AbstractGenericDao
 * 
 * @author bbeverly
 * @see AbstractGenericDao
 */
@Repository
public class HibernateApplicationDao implements ApplicationDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateApplicationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

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
	@Transactional(readOnly = true)
	public Application retrieveById(int id) {
		return (Application) getActiveAppCriteria().add(Restrictions.eq("id",id)).uniqueResult();
	}

	@Override
	public Application retrieveByName(String name, int teamId) {
		return (Application) getActiveAppCriteria().add(Restrictions.eq("name",name))
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
			return null;
		}
		
		List<Integer> ints = new ArrayList<>();
		
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
	public List<Integer> getTopXVulnerableAppsFromList(int numApps,
			List<Integer> applicationIdList) {
		return sessionFactory.getCurrentSession()
				.createQuery("SELECT application.id as id " +
						" FROM Application as application join application.vulnerabilities as vulnerability " +
						" WHERE application.id IN (:applicationIdList) AND " +
						"   application.active = true AND " +
						" 	vulnerability.active = true AND " +
						"   vulnerability.isFalsePositive = false " +
						 "GROUP BY application.id " +
						 "ORDER BY count(vulnerability) desc")
				.setParameterList("applicationIdList", applicationIdList)
				.setMaxResults(numApps)
				.list();
	}
}
