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

import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.User;

/**
 * Hibernate User DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author dshannon
 * @see AbstractGenericDao
 */
@Repository
public class HibernateUserDao implements UserDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateUserDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<User> retrieveAll() {
		return sessionFactory.getCurrentSession().createQuery("from User user order by user.name")
				.list();
	}

	@Override
	public User retrieveById(int id) {
		return (User) sessionFactory.getCurrentSession().get(User.class, id);
	}

	@Override
	public User retrieveByName(String name) {
		return (User) sessionFactory.getCurrentSession()
				.createQuery("from User user where user.name = :name").setString("name", name)
				.uniqueResult();
	}

	@Override
	public void saveOrUpdate(User user) {
		if (user.getId() != null) {
			sessionFactory.getCurrentSession().merge(user);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(user);
		}
	}

	@Override
	public void deleteById(int id) {
		sessionFactory.getCurrentSession().delete(retrieveById(id));
	}

}
