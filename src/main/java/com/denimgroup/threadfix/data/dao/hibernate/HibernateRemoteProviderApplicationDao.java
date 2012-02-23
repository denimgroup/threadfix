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

import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;

@Repository
public class HibernateRemoteProviderApplicationDao implements RemoteProviderApplicationDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateRemoteProviderApplicationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public RemoteProviderApplication retrieveById(int id) {
		return (RemoteProviderApplication) sessionFactory.getCurrentSession().get(RemoteProviderApplication.class, id);
	}

	@Override
	public void saveOrUpdate(RemoteProviderApplication remoteProviderApplication) {
		sessionFactory.getCurrentSession().saveOrUpdate(remoteProviderApplication);
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<RemoteProviderApplication> retrieveAllWithTypeId(int id) {
		return sessionFactory.getCurrentSession()
			.createQuery("from RemoteProviderApplication app where app.remoteProviderType = :type")
			.setInteger("type", id).list();
	}

	@Override
	public void deleteRemoteProviderApplication(RemoteProviderApplication app) {
		sessionFactory.getCurrentSession().delete(app);
	}

}
