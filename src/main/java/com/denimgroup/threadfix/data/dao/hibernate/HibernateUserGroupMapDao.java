package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.UserGroupMapDao;
import com.denimgroup.threadfix.data.entities.AccessGroup;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserGroupMap;

@Repository
public class HibernateUserGroupMapDao implements UserGroupMapDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateUserGroupMapDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<UserGroupMap> retrieveAll() {
		return getActiveCriteria().addOrder(Order.asc("id")).list();
	}

	@Override
	public UserGroupMap retrieveById(int id) {
		return (UserGroupMap) getActiveCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}

	private Criteria getActiveCriteria() {
		return sessionFactory.getCurrentSession()
							 .createCriteria(UserGroupMap.class)
							 .add(Restrictions.eq("active",true));
	}
	
	@Override
	public void saveOrUpdate(UserGroupMap map) {
		sessionFactory.getCurrentSession().saveOrUpdate(map);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<User> getUsersForGroup(int groupId) {
		return (List<User>) sessionFactory.getCurrentSession()
				.createQuery("select user from UserGroupMap map " +
						"where map.accessGroup = :group " +
						"and map.active = true")
				.setInteger("group", groupId)
				.list();
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<AccessGroup> getGroupsForUser(int userId) {
		return (List<AccessGroup>) sessionFactory.getCurrentSession()
				.createQuery("select accessGroup from UserGroupMap map " +
						"where map.user = :user " +
						"and map.active = true")
				.setInteger("user", userId)
				.list();
	}
	
	@Override
	public UserGroupMap retrieveByUserAndGroup(int userId, int groupId) {
		return (UserGroupMap) sessionFactory.getCurrentSession()
				 .createQuery("from UserGroupMap map " +
						"where map.user = :user " +
						"and map.accessGroup = :group")
						.setInteger("user", userId)
						.setInteger("group", groupId)
				 .uniqueResult();
	}
}
