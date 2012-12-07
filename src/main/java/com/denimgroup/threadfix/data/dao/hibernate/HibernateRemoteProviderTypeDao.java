////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.RemoteProviderTypeDao;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;

@Repository
public class HibernateRemoteProviderTypeDao implements RemoteProviderTypeDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateRemoteProviderTypeDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<RemoteProviderType> retrieveAll() {
		return sessionFactory.getCurrentSession().createQuery("from RemoteProviderType " +
				"remoteProviderType order by remoteProviderType.name").list();
	}

	@Override
	public RemoteProviderType retrieveById(int id) {
		return (RemoteProviderType) sessionFactory.getCurrentSession().get(RemoteProviderType.class, id);
	}

	@Override
	public RemoteProviderType retrieveByName(String name) {
		return (RemoteProviderType) sessionFactory.getCurrentSession()
			.createQuery("from RemoteProviderType type where type.name = :name")
			.setString("name", name).uniqueResult();
	}

	@Override
	public void saveOrUpdate(RemoteProviderType remoteProviderType) {
		if (remoteProviderType.getId() != null) {
			sessionFactory.getCurrentSession().merge(remoteProviderType);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(remoteProviderType);
		}
	}

}
