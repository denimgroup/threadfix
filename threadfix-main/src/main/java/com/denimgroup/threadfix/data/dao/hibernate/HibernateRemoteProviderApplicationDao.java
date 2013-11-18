////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.RemoteProviderApplicationDao;
import com.denimgroup.threadfix.data.entities.DeletedRemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;

@Repository
public class HibernateRemoteProviderApplicationDao implements RemoteProviderApplicationDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateRemoteProviderApplicationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@Override
	public void delete(RemoteProviderApplication app) {
		sessionFactory.getCurrentSession().save(new DeletedRemoteProviderApplication(app));
		sessionFactory.getCurrentSession().delete(app);
	}

    @NotNull
	@Override
	@SuppressWarnings("unchecked")
	public List<RemoteProviderApplication> retrieveAllWithTypeId(int id) {
		return getActiveRPACriteria().add(Restrictions.eq("remoteProviderType.id", id))
				.addOrder(Order.asc("nativeId"))
				.list();
	}
	
	@Override
	public RemoteProviderApplication retrieveById(int id) {
		return (RemoteProviderApplication) getActiveRPACriteria().add(Restrictions.eq("id",id)).uniqueResult();
	}

	@Override
	public void saveOrUpdate(RemoteProviderApplication remoteProviderApplication) {
		sessionFactory.getCurrentSession().saveOrUpdate(remoteProviderApplication);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<RemoteProviderApplication> retrieveAllWithMappings() {
		return (List<RemoteProviderApplication>) getActiveRPACriteria()
							 .add(Restrictions.isNotNull("application"))
							 .list();
	}
	
	public Criteria getActiveRPACriteria() {
		return sessionFactory.getCurrentSession()
				.createCriteria(RemoteProviderApplication.class)
				.add(Restrictions.eq("active",true));
	}
}
