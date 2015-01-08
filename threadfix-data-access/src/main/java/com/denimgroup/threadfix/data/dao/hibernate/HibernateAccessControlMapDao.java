////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.AccessControlMapDao;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;

@Repository
public class HibernateAccessControlMapDao implements AccessControlMapDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateAccessControlMapDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<AccessControlTeamMap> retrieveAllMapsForUser(Integer id) {
		return sessionFactory.getCurrentSession()
				 .createCriteria(AccessControlTeamMap.class)
				 .createAlias("organization", "orgAlias")
				 .createAlias("user", "userAlias")
				 .add(Restrictions.eq("userAlias.id",id))
				 .add(Restrictions.eq("active",true))
				 .addOrder(Order.asc("orgAlias.name"))
				 .list();
	}
	
	@Override
	public AccessControlTeamMap retrieveTeamMapById(int id) {
		return (AccessControlTeamMap) sessionFactory.getCurrentSession()
				 .createCriteria(AccessControlTeamMap.class)
				 .add(Restrictions.eq("id",id))
				 .add(Restrictions.eq("active",true))
				 .uniqueResult();
	}
	
	@Override
	public AccessControlApplicationMap retrieveAppMapById(int id) {
		return (AccessControlApplicationMap) sessionFactory.getCurrentSession()
				.createCriteria(AccessControlApplicationMap.class)
				.add(Restrictions.eq("id",id))
				.add(Restrictions.eq("active",true))
				.uniqueResult();
	}

	@Override
	public void saveOrUpdate(AccessControlTeamMap map) {
		if (map != null && map.getId() != null) {
			sessionFactory.getCurrentSession().merge(map);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(map);
		}
	}

	@Override
	public void saveOrUpdate(AccessControlApplicationMap map) {
		if (map != null && map.getId() != null) {
			sessionFactory.getCurrentSession().merge(map);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(map);
		}
	}

	@Override
	public AccessControlTeamMap retrieveTeamMapByUserTeamAndRole(int userId,
			int organizationId, int roleId) {
		return (AccessControlTeamMap) sessionFactory.getCurrentSession()
				 .createCriteria(AccessControlTeamMap.class)
				 .createAlias("organization", "orgAlias")
				 .createAlias("role", "roleAlias")
				 .createAlias("user", "userAlias")
				 .add(Restrictions.eq("userAlias.id",userId))
				 .add(Restrictions.eq("roleAlias.id",roleId))
				 .add(Restrictions.eq("orgAlias.id",organizationId))
				 .add(Restrictions.eq("active",true))
				 .uniqueResult();
	}

	@Override
	public AccessControlApplicationMap retrieveAppMapByUserAppAndRole(int userId,
			int applicationId, int roleId) {
		return (AccessControlApplicationMap) sessionFactory.getCurrentSession()
				 .createCriteria(AccessControlApplicationMap.class)
				 .createAlias("application", "appAlias")
				 .createAlias("role", "roleAlias")
				 .createAlias("accessControlTeamMap", "parentMap")
				 .createAlias("parentMap.user", "userAlias")
				 .add(Restrictions.eq("userAlias.id",userId))
				 .add(Restrictions.eq("roleAlias.id",roleId))
				 .add(Restrictions.eq("appAlias.id",applicationId))
				 .add(Restrictions.eq("active",true))
				 .uniqueResult();
	}
}
