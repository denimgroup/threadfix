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
}
