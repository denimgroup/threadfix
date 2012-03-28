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

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;

/**
 * Hibernate SecurityEvent DAO implementation. Most basic methods are
 * implemented in the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateSecurityEventDao implements SecurityEventDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateSecurityEventDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<SecurityEvent> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from SecurityEvent securityEvent order by securityEvent.name").list();
	}

	@Override
	public SecurityEvent retrieveById(int id) {
		return (SecurityEvent) sessionFactory.getCurrentSession().get(SecurityEvent.class, id);
	}

	@Override
	public SecurityEvent retrieveByName(String name) {
		return (SecurityEvent) sessionFactory.getCurrentSession()
				.createQuery("from SecurityEvent securityEvent where securityEvent.name = :name")
				.setString("name", name).uniqueResult();
	}

	@Override
	public SecurityEvent retrieveByNativeIdAndWafId(String nativeId, String wafId) {
		return (SecurityEvent) sessionFactory.getCurrentSession()
			.createQuery("from SecurityEvent securityEvent where securityEvent.nativeId = :nativeId " +
					"and securityEvent.wafRule.waf = :wafId")
			.setString("nativeId", nativeId).setString("wafId", wafId).uniqueResult();
	}
	
	@Override
	public void saveOrUpdate(SecurityEvent securityEvent) {
		sessionFactory.getCurrentSession().saveOrUpdate(securityEvent);
	}
	

}
