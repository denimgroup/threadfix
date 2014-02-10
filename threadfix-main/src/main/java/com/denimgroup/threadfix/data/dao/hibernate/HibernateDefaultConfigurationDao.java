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

import java.util.List;

import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;

@Repository
@Transactional
public class HibernateDefaultConfigurationDao implements DefaultConfigurationDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateDefaultConfigurationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
 
	@SuppressWarnings("unchecked")
	@Override
	public List<DefaultConfiguration> retrieveAll() {
		return (List<DefaultConfiguration>) sessionFactory.getCurrentSession()
				.createCriteria(DefaultConfiguration.class)
				.addOrder(Order.asc("id"))
				.list();
	}
	
	@Override
	public void saveOrUpdate(DefaultConfiguration config) {
		if (config != null && config.getId() != null) {
			sessionFactory.getCurrentSession().merge(config);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(config);
		}
	}

	@Override
	public void delete(DefaultConfiguration config) {
		sessionFactory.getCurrentSession().delete(config);
	}
	
}
