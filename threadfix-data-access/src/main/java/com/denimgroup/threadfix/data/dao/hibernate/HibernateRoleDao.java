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

	@Autowired
	private SessionFactory sessionFactory;

	@Override
	@SuppressWarnings("unchecked")
	public List<Role> retrieveAll() {
		return getActiveRoleCriteria().addOrder(Order.asc("displayName")).list();
	}

	@Override
	public Role retrieveById(int id) {
		return (Role) getActiveRoleCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}

    @Override
    public List<Role> retrieveAllActive() {
        return retrieveAll();
    }

    @Override
	public Role retrieveByName(String name) {
		return (Role) getActiveRoleCriteria().add(Restrictions.eq("displayName", name)).uniqueResult();
	}

	@Override
	public void saveOrUpdate(Role role) {
		if (role != null && role.getId() != null) {
			sessionFactory.getCurrentSession().merge(role);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(role);
		}
	}
	
	private Criteria getActiveRoleCriteria() {
		return sessionFactory.getCurrentSession()
				.createCriteria(Role.class)
				.add(Restrictions.eq("active", true));
	}

}
