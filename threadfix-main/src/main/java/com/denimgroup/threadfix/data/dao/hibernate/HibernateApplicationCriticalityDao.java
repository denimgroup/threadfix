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

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ApplicationCriticalityDao;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;

/**
 * 
 * @author mcollins
 *
 */
@Repository
public class HibernateApplicationCriticalityDao implements ApplicationCriticalityDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateApplicationCriticalityDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<ApplicationCriticality> retrieveAll() {
		return sessionFactory.getCurrentSession()
			.createQuery("from ApplicationCriticality criticality order by id").list();
	}

	@Override
	public ApplicationCriticality retrieveById(int id) {
		return (ApplicationCriticality) sessionFactory.getCurrentSession().get(
				ApplicationCriticality.class, id);
	}

	@Override
	public ApplicationCriticality retrieveByName(String name) {
		return (ApplicationCriticality) sessionFactory.getCurrentSession()
				.createQuery("from ApplicationCriticality criticality where " +
						"criticality.name = :name").setString("name", name)
				.uniqueResult();
	}

}
