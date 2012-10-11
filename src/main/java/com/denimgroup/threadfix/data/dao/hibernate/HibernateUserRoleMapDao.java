package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.UserRoleMapDao;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserRoleMap;

@Repository
public class HibernateUserRoleMapDao implements UserRoleMapDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateUserRoleMapDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<UserRoleMap> retrieveAll() {
		return getActiveCriteria().addOrder(Order.asc("id")).list();
	}

	@Override
	public UserRoleMap retrieveById(int id) {
		return (UserRoleMap) getActiveCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}

	private Criteria getActiveCriteria() {
		return sessionFactory.getCurrentSession()
							 .createCriteria(UserRoleMap.class)
							 .add(Restrictions.eq("active",true));
	}
	
	@Override
	public void saveOrUpdate(UserRoleMap map) {
		sessionFactory.getCurrentSession().saveOrUpdate(map);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<User> getUsersForRole(int roleId) {
		return (List<User>) sessionFactory.getCurrentSession()
				.createQuery("select user from UserRoleMap map " +
						"where map.role = :role " +
						"and map.active = true")
				.setInteger("role", roleId)
				.list();
	}

	@SuppressWarnings("unchecked")
	@Override
	@Transactional
	public List<Role> getRolesForUser(int userId) {
		return (List<Role>) sessionFactory.getCurrentSession()
				.createQuery("select role from UserRoleMap map " +
						"where map.user = :user " +
						"and map.active = true")
				.setInteger("user", userId)
				.list();
	}
	
	@Override
	public UserRoleMap retrieveByUserAndRole(int userId, int roleId) {
		return (UserRoleMap) sessionFactory.getCurrentSession()
				 .createQuery("from UserRoleMap map " +
						"where map.user = :user " +
						"and map.role = :role")
						.setInteger("user", userId)
						.setInteger("role", roleId)
				 .uniqueResult();
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<UserRoleMap> retrieveByRoleName(String roleName) {
		return (List<UserRoleMap>) sessionFactory.getCurrentSession()
				.createCriteria(UserRoleMap.class)
				.add(Restrictions.eq("active", true))
				.createAlias("role", "roleAlias")
				.add(Restrictions.eq("roleAlias.name", roleName))
				.list();
	}
}
