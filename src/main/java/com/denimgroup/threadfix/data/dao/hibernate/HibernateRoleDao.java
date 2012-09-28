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

import com.denimgroup.threadfix.data.dao.RoleDao;
import com.denimgroup.threadfix.data.entities.Role;

/**
 * Hibernate Role DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author dshannon
 * @see AbstractGenericDao
 */
@Repository
public class HibernateRoleDao implements RoleDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateRoleDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Role> retrieveAll() {
		return sessionFactory.getCurrentSession()
							 .createQuery("from Role role order by role.name")
							 .list();
	}

	@Override
	public Role retrieveById(int id) {
		return (Role) sessionFactory.getCurrentSession().get(Role.class, id);
	}

	@Override
	public Role retrieveByName(String name) {
		return (Role) sessionFactory.getCurrentSession()
									.createQuery("from Role role where role.name = :name").setString("name", name)
									.uniqueResult();
	}

	@Override
	public void saveOrUpdate(Role role) {
		sessionFactory.getCurrentSession().saveOrUpdate(role);
	}

	@Override
	public boolean isAdmin(int id) {
		String result = (String) sessionFactory.getCurrentSession()
				.createQuery("select name from Role where id = :id")
				.setInteger("id", id)
				.uniqueResult();
		
		return result != null && result.equals(Role.ADMIN);
	}
}
