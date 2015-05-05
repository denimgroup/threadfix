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

import com.denimgroup.threadfix.data.dao.AccessControlMapDao;
import com.denimgroup.threadfix.data.entities.AccessControlApplicationMap;
import com.denimgroup.threadfix.data.entities.AccessControlTeamMap;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

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
	@SuppressWarnings("unchecked")
	@Override
	public List<AccessControlTeamMap> retrieveAllMapsForGroup(Integer id) {
		return sessionFactory.getCurrentSession()
				 .createCriteria(AccessControlTeamMap.class)
				 .createAlias("organization", "orgAlias")
				 .createAlias("group", "groupAlias")
				 .add(Restrictions.eq("groupAlias.id",id))
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
		return (AccessControlTeamMap)
				getLookupCriteriaBase(AccessControlTeamMap.class, roleId)
				 .createAlias("organization", "orgAlias")
				 .createAlias("user", "userAlias")
				 .add(Restrictions.eq("userAlias.id",userId))
				 .add(Restrictions.eq("orgAlias.id",organizationId))
				 .uniqueResult();
	}

	@Override
	public AccessControlApplicationMap retrieveAppMapByUserAppAndRole(int userId,
			int applicationId, int roleId) {
		return (AccessControlApplicationMap)
				getLookupCriteriaBase(AccessControlApplicationMap.class, roleId)
				 .createAlias("application", "appAlias")
				 .createAlias("accessControlTeamMap", "parentMap")
				 .createAlias("parentMap.user", "userAlias")
				 .add(Restrictions.eq("userAlias.id",userId))
				 .add(Restrictions.eq("appAlias.id",applicationId))
				 .uniqueResult();
	}

	@Override
	public AccessControlTeamMap retrieveTeamMapByGroupTeamAndRole(int groupId,
																  int organizationId, int roleId) {
		return (AccessControlTeamMap)
				getLookupCriteriaBase(AccessControlTeamMap.class, roleId)
				 .createAlias("group", "groupAlias")
				 .createAlias("organization", "orgAlias")
				 .add(Restrictions.eq("groupAlias.id", groupId))
				 .add(Restrictions.eq("orgAlias.id",organizationId))
				 .uniqueResult();
	}

	@Override
	public AccessControlApplicationMap retrieveAppMapByGroupAppAndRole(int groupId,
																	   int applicationId, int roleId) {
		return (AccessControlApplicationMap)
				getLookupCriteriaBase(AccessControlApplicationMap.class, roleId)
				 .createAlias("application", "appAlias")
				 .createAlias("accessControlTeamMap", "parentMap")
				 .createAlias("parentMap.group", "groupAlias")
				 .add(Restrictions.eq("groupAlias.id",groupId))
				 .add(Restrictions.eq("appAlias.id",applicationId))
				 .uniqueResult();
	}

	private Criteria getLookupCriteriaBase(Class<?> targetClass, Integer roleId) {
		return sessionFactory.getCurrentSession()
				.createCriteria(targetClass)
				.createAlias("role", "roleAlias")
				.add(Restrictions.eq("roleAlias.id",roleId))
				.add(Restrictions.eq("active",true));
	}
}
