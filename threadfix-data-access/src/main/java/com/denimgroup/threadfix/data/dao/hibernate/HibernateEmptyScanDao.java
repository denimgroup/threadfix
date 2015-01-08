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

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.entities.EmptyScan;

/**
 * Hibernate EmptyScan DAO implementation. Most basic methods are
 * implemented in the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateEmptyScanDao implements EmptyScanDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateEmptyScanDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<EmptyScan> retrieveAllUnprocessed() {
		return sessionFactory.getCurrentSession()
			.createQuery("from EmptyScan emptyScan where emptyScan.alreadyProcessed = false").list();
	}

	@Override
	public EmptyScan retrieveById(Integer emptyScanId) {
		return (EmptyScan) sessionFactory.getCurrentSession().get(EmptyScan.class, emptyScanId);
	}

	@Override
	public void saveOrUpdate(EmptyScan emptyScan) {
		sessionFactory.getCurrentSession().saveOrUpdate(emptyScan);
	}
}
