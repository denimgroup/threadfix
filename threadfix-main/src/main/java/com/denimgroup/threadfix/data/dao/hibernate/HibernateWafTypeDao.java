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

import com.denimgroup.threadfix.data.dao.WafTypeDao;
import com.denimgroup.threadfix.data.entities.WafType;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate WafType DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateWafTypeDao implements WafTypeDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateWafTypeDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<WafType> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from WafType wafType order by wafType.name").list();
	}

	@Override
	public WafType retrieveById(int id) {
		return (WafType) sessionFactory.getCurrentSession().get(WafType.class, id);
	}

	@Override
	public WafType retrieveByName(String name) {
		return (WafType) sessionFactory.getCurrentSession()
				.createQuery("from WafType wafType where wafType.name = :name")
				.setString("name", name).uniqueResult();
	}

}
