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

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.ChannelType;

@Repository
public class HibernateChannelTypeDao implements ChannelTypeDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateChannelTypeDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public void deleteById(int id) {
		sessionFactory.getCurrentSession().delete(retrieveById(id));
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<ChannelType> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from ChannelType channelType order by channelType.name").list();
	}

	@Override
	public ChannelType retrieveById(int id) {
		return (ChannelType) sessionFactory.getCurrentSession().get(ChannelType.class, id);
	}

	@Override
	public ChannelType retrieveByName(String name) {
		return (ChannelType) sessionFactory.getCurrentSession()
				.createQuery("from ChannelType channelType where channelType.name = :name")
				.setString("name", name).uniqueResult();
	}

	@Override
	public void saveOrUpdate(ChannelType channelType) {
		sessionFactory.getCurrentSession().saveOrUpdate(channelType);
	}
}
