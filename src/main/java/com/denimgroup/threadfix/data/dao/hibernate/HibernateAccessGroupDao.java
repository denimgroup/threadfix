package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.AccessGroupDao;
import com.denimgroup.threadfix.data.entities.AccessGroup;

@Repository
public class HibernateAccessGroupDao implements AccessGroupDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateAccessGroupDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<AccessGroup> retrieveAll() {
		return getActiveGroupCriteria().addOrder(Order.asc("name")).list();
	}

	@Override
	public AccessGroup retrieveById(int id) {
		return (AccessGroup) getActiveGroupCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}
	
	@Override
	public AccessGroup retrieveByName(String name) {
		return (AccessGroup) getActiveGroupCriteria().add(Restrictions.eq("name", name)).uniqueResult();
	}
	
	private Criteria getActiveGroupCriteria() {
		return sessionFactory.getCurrentSession()
							 .createCriteria(AccessGroup.class)
							 .add(Restrictions.eq("active",true));
	}
	
	@Override
	public void saveOrUpdate(AccessGroup group) {
		if (group != null && group.getId() != null) {
			sessionFactory.getCurrentSession().merge(group);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(group);
		}
	}
}
