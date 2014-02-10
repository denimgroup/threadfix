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

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.APIKeyDao;
import com.denimgroup.threadfix.data.entities.APIKey;

/**
 * 
 * @author mcollins
 * @see AbstractGenericDao
 */
@Repository
public class HibernateAPIKeyDao implements APIKeyDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateAPIKeyDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<APIKey> retrieveAll() {
		return getActiveAPIKeyCriteria().addOrder(Order.asc("id")).list();
	}

	@Override
	public APIKey retrieveById(int id) {
		return (APIKey) getActiveAPIKeyCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}

	@Override
	public APIKey retrieveByKey(String key) {
		return (APIKey) getActiveAPIKeyCriteria().add(Restrictions.eq("apiKey", key)).uniqueResult();
	}
	
	private Criteria getActiveAPIKeyCriteria() {
		return sessionFactory.getCurrentSession()
							 .createCriteria(APIKey.class)
							 .add(Restrictions.eq("active",true));
	}
	
	@Override
	public void saveOrUpdate(APIKey apiKey) {
		sessionFactory.getCurrentSession().saveOrUpdate(apiKey);
	}
}
