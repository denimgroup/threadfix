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

import java.util.List;
import java.util.Set;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.entities.Organization;

/**
 * Hibernate Organization DAO implementation. Most basic methods are implemented
 * in the AbstractGenericDao
 * 
 * @author jraim
 * @see AbstractGenericDao
 */
@Repository
public class HibernateOrganizationDao implements OrganizationDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateOrganizationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Organization> retrieveAllActive() {
		return sessionFactory.getCurrentSession()
				.createQuery("from Organization org where org.active = 1 order by org.name").list();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Organization> retrieveAllNoOrder() {
		return sessionFactory.getCurrentSession().createQuery("from Organization org").list();
	}

	@Override
	public Organization retrieveById(int id) {
		return (Organization) sessionFactory.getCurrentSession().get(Organization.class, id);
	}

	@Override
	public Organization retrieveByName(String name) {
		return (Organization) sessionFactory.getCurrentSession()
				.createQuery("from Organization org where org.name = :name")
				.setString("name", name).uniqueResult();
	}

	@Override
	public void saveOrUpdate(Organization organization) {
		if (organization.getId() != null) {
			sessionFactory.getCurrentSession().merge(organization);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(organization);
		}
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<Organization> retrieveAllActiveFilter(Set<Integer> authenticatedTeamIds) {
		return sessionFactory.getCurrentSession()
				.createQuery("from Organization org where org.active = 1 and org.id in (:teams) order by org.name")
				.setParameterList("teams", authenticatedTeamIds).list();
	}

}
