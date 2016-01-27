////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.AbstractNamedObjectDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.User;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate User DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 *
 * @author dshannon
 */
@Repository
public class HibernateUserDao
		extends AbstractNamedObjectDao<User>
		implements UserDao {

	@Autowired
	public HibernateUserDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Override
	protected Order getOrder() {
		return Order.asc("name");
	}

	@Override
	public User retrieveLdapUser(String name) {
		return (User) getActiveUserCriteria()
				.add(Restrictions.eq("name", name))
				.add(Restrictions.eq("isLdapUser", true))
				.uniqueResult();
	}

    /**
     * @param name
     * @return
     */
    @Override
    public User retrieveLocalUser(String name) {
        return (User) getActiveUserCriteria()
                .add(Restrictions.eq("name", name))
                .add(Restrictions.eq("isLdapUser", false))
                .uniqueResult();
    }

    @Override
	protected Class<User> getClassReference() {
		return User.class;
	}

	private Criteria getActiveUserCriteria() {
		return sessionFactory.getCurrentSession().createCriteria(User.class).add(Restrictions.eq("active", true));
	}

	public boolean canRemovePermissionFromRole(Integer id, String string) {
		Long result = (Long) sessionFactory.getCurrentSession()
				.createCriteria(User.class)
				.createAlias("globalRole", "roleAlias")
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("isLdapUser", false))
				.add(Restrictions.eq("roleAlias." + string, true))
				.add(Restrictions.ne("roleAlias.id", id))
				.setProjection(Projections.rowCount())
				.uniqueResult();

		if (result == null || result == 0) {
			// we also need to do a lookup on groups
			result += (Long) sessionFactory.getCurrentSession()
					.createCriteria(User.class)
					.createAlias("groups", "groupAlias")
					.createAlias("groupAlias.globalRole", "roleAlias")
					.add(Restrictions.eq("active", true))
					.add(Restrictions.eq("isLdapUser", false))
					.add(Restrictions.eq("groupAlias.active", true))
					.add(Restrictions.eq("roleAlias." + string, true))
					.add(Restrictions.ne("roleAlias.id", id))
					.setProjection(Projections.rowCount())
					.uniqueResult();
		}

		return result != null && result > 0;
	}

	public boolean canRemovePermissionFromUser(Integer id, String string) {
		Long result = (Long) sessionFactory.getCurrentSession()
				.createCriteria(User.class)
				.createAlias("globalRole", "roleAlias")
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("isLdapUser", false))
				.add(Restrictions.eq("roleAlias." + string, true))
				.add(Restrictions.ne("id", id))
				.setProjection(Projections.rowCount())
				.uniqueResult();

		if (result == null || result == 0) {
			// we also need to do a lookup on groups
			result += (Long) sessionFactory.getCurrentSession()
					.createCriteria(User.class)
					.createAlias("groups", "groupAlias")
					.createAlias("groupAlias.globalRole", "roleAlias")
					.add(Restrictions.eq("active", true))
					.add(Restrictions.eq("isLdapUser", false))
					.add(Restrictions.eq("groupAlias.active", true))
					.add(Restrictions.eq("roleAlias." + string, true))
					.add(Restrictions.ne("id", id))
					.setProjection(Projections.rowCount())
					.uniqueResult();
		}

		return result != null && result > 0;
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<User> retrieveOrgPermissibleUsers(Integer orgId) {

		List<User> globalUserList = getActiveUserCriteria()
				.add(Restrictions.eq("hasGlobalGroupAccess", true))
				.addOrder(Order.asc("name"))
				.list();
		List<User> orgUserList = getActiveUserCriteria()
				.add(Restrictions.eq("hasGlobalGroupAccess", false))
				.createAlias("accessControlTeamMaps", "teamMap")
				.add(Restrictions.eq("teamMap.organization.id",orgId))
				.addOrder(Order.asc("name"))
				.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY)
				.list();
		globalUserList.addAll(orgUserList);

		return globalUserList;

	}

	@SuppressWarnings("unchecked")
	@Override
	public List<User> retrieveAppPermissibleUsers(Integer orgId, Integer appId) {

		List<User> globalUserList = getActiveUserCriteria()
				.add(Restrictions.eq("hasGlobalGroupAccess", true))
				.addOrder(Order.asc("name"))
				.list();
		List<User> appAllUserList = getActiveUserCriteria()
				.add(Restrictions.eq("hasGlobalGroupAccess", false))
				.createAlias("accessControlTeamMaps", "teamMap")
				.add(Restrictions.and(Restrictions.eq("teamMap.allApps", true),
						Restrictions.eq("teamMap.organization.id", orgId)))
				.addOrder(Order.asc("name"))
				.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY)
				.list();
		List<User> appUserList = getActiveUserCriteria()
				.add(Restrictions.eq("hasGlobalGroupAccess", false))
				.createAlias("accessControlTeamMaps", "teamMap")
				.createAlias("teamMap.accessControlApplicationMaps", "appMap")
				.add(Restrictions.and(Restrictions.eq("teamMap.allApps", false),
						Restrictions.eq("appMap.application.id",appId)))
				.addOrder(Order.asc("name"))
				.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY)
				.list();
		globalUserList.addAll(appUserList);
		for (User u: appAllUserList)
			if (!globalUserList.contains(u)) globalUserList.add(u);

		return globalUserList;
	}

	@Override
	public List<User> retrievePage(int page, int numberToShow) {
		return getActiveUserCriteria()
				.addOrder(Order.asc("name"))
				.setMaxResults(numberToShow)
				.setFirstResult((page - 1) * numberToShow)
				.list();
	}

	@Override
	public Long countUsers(String searchString) {
		Criteria criteria = getActiveUserCriteria()
				.setProjection(Projections.rowCount());

		if (searchString != null) {
			criteria.add(Restrictions.or(
					Restrictions.like("name", "%" + searchString + "%"),
					Restrictions.like("displayName", "%" + searchString + "%")
			));
		}

		return (Long) criteria
				.uniqueResult();
	}

	@Override
	public Long countUsers() {
		return (Long) getActiveUserCriteria()
				.setProjection(Projections.rowCount())
				.uniqueResult();
	}

	@Override
	public boolean canRemovePermissionFromUserAndGroup(Integer userId, Integer groupId, String string) {
		Long result = (Long) sessionFactory.getCurrentSession()
				.createCriteria(User.class)
				.createAlias("globalRole", "roleAlias")
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("isLdapUser", false))
				.add(Restrictions.eq("roleAlias." + string, true))
				.add(Restrictions.ne("id", userId))
				.setProjection(Projections.rowCount())
				.uniqueResult();

		if (result == null || result == 0) {
			// we also need to do a lookup on groups
			result += (Long) sessionFactory.getCurrentSession()
					.createCriteria(User.class)
					.createAlias("groups", "groupAlias")
					.createAlias("groupAlias.globalRole", "roleAlias")
					.add(Restrictions.eq("active", true))
					.add(Restrictions.eq("isLdapUser", false))
					.add(Restrictions.eq("groupAlias.active", true))
					.add(Restrictions.ne("groupAlias.id", groupId))
					.add(Restrictions.eq("roleAlias." + string, true))
					.add(Restrictions.ne("id", userId))
					.setProjection(Projections.rowCount())
					.uniqueResult();
		}

		return result != null && result > 0;
	}

	@Override
	public List<User> getSearchResults(String searchString, int number, int page) {
		return (List<User>) getSession().createCriteria(User.class)
				.add(Restrictions.eq("active", true))
				.add(Restrictions.or(
						Restrictions.like("name", "%" + searchString + "%"),
						Restrictions.like("displayName", "%" + searchString + "%")
				)).setMaxResults(number)
				.setFirstResult((page - 1) * number)
				.addOrder(Order.asc("name"))
				.list();
	}

	@Override
	public List<User> loadUsersForRole(Integer id) {
		return getSession().createCriteria(User.class)
				.createAlias("globalRole", "roleAlias")
				.add(Restrictions.eq("roleAlias.id", id))
				.list();
	}
}
