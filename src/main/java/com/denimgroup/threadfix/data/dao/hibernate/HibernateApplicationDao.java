////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.entities.Application;

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
	public void deleteById(int id) {
		sessionFactory.getCurrentSession().delete(retrieveById(id));
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
		return sessionFactory.getCurrentSession()
				.createQuery("from Application app where active = 1 order by app.name").list();
	}

	@Override
	public Application retrieveById(int id) {
		return (Application) sessionFactory.getCurrentSession().get(Application.class, id);
	}

	@Override
	public Application retrieveByName(String name) {
		return (Application) sessionFactory.getCurrentSession()
				.createQuery("from Application app where app.name = :name").setString("name", name)
				.uniqueResult();
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
		
		List<Integer> ints = new ArrayList<Integer>();
		
		for (int i = 1; i < 6; i++) {
			long result = (Long) sessionFactory.getCurrentSession()
				.createQuery("select count(*) from Vulnerability vuln " +
						"where genericSeverity.intValue = :value " +
						"and application = :app and active = true")
				.setInteger("value", i)
				.setInteger("app", application.getId())
				.uniqueResult();

			ints.add((int) result);
		}
		
		long result = (Long) sessionFactory.getCurrentSession()
				.createQuery("select count(*) from Vulnerability vuln " +
						"where application = :app and active = true")
				.setInteger("app", application.getId())
				.uniqueResult();
		ints.add((int) result);
		return ints;
	}

}
