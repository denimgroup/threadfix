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
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;

/**
 * Hibernate Channel DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateApplicationChannelDao implements ApplicationChannelDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateApplicationChannelDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<ApplicationChannel> retrieveAll() {
		return sessionFactory.getCurrentSession().createCriteria(ApplicationChannel.class)
				.createAlias("channelType", "ct").createAlias("application", "app")
				.createAlias("application.organization", "org").addOrder(Order.asc("org.name"))
				.addOrder(Order.asc("app.name")).addOrder(Order.asc("ct.name")).list();
	}

	@Override
	public ApplicationChannel retrieveById(int id) {
		return (ApplicationChannel) sessionFactory.getCurrentSession().get(
				ApplicationChannel.class, id);
	}

	@Override
	public void saveOrUpdate(ApplicationChannel applicationChannel) {
		sessionFactory.getCurrentSession().saveOrUpdate(applicationChannel);
	}

	@Override
	public void deleteById(int id) {
		sessionFactory.getCurrentSession().delete(retrieveById(id));
	}

	@Override
	public ApplicationChannel retrieveByAppIdAndChannelId(Integer appId, Integer channelId) {
		return (ApplicationChannel) sessionFactory
				.getCurrentSession()
				.createQuery(
						"from ApplicationChannel appChannel where appChannel.application = :appId "
								+ "and appChannel.channelType = :channelId")
				.setInteger("appId", appId).setInteger("channelId", channelId).uniqueResult();
	}

}
