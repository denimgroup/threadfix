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

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * Hibernate Scan DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author mcollins
 * @see AbstractGenericDao
 */
@Repository
public class HibernateScanDao implements ScanDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateScanDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from Scan scan order by scan.importTime desc").list();
	}

	@Override
	public Scan retrieveById(int id) {
		return (Scan) sessionFactory.getCurrentSession().get(Scan.class, id);
	}

	@Override
	public void saveOrUpdate(Scan scan) {
		sessionFactory.getCurrentSession().saveOrUpdate(scan);
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> retrieveByApplicationIdList(List<Integer> applicationIdList) {
		return sessionFactory.getCurrentSession()
			.createQuery("from Scan scan where scan.application.id in (:idList)").setParameterList("idList", applicationIdList).list();
	}
}
