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

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.WafDao;
import com.denimgroup.threadfix.data.entities.Waf;

/**
 * Hibernate Waf DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateWafDao implements WafDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateWafDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Waf> retrieveAll() {
		return sessionFactory.getCurrentSession().createQuery("from Waf waf order by waf.name")
				.list();
	}

	@Override
	public Waf retrieveById(int id) {
		return (Waf) sessionFactory.getCurrentSession().get(Waf.class, id);
	}

	@Override
	public Waf retrieveByName(String name) {
		return (Waf) sessionFactory.getCurrentSession()
				.createQuery("from Waf waf where waf.name = :name").setString("name", name)
				.uniqueResult();
	}

	@Override
	public void saveOrUpdate(Waf waf) {
		if (waf.getId() != null) {
			sessionFactory.getCurrentSession().merge(waf);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(waf);
		}
	}

	@Override
	public void deleteById(int id) {
		sessionFactory.getCurrentSession().delete(retrieveById(id));
	}
}
