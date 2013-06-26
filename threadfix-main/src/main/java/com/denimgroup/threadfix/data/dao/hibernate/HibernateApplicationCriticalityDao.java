package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ApplicationCriticalityDao;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;

/**
 * 
 * @author mcollins
 *
 */
@Repository
public class HibernateApplicationCriticalityDao implements ApplicationCriticalityDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateApplicationCriticalityDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<ApplicationCriticality> retrieveAll() {
		return sessionFactory.getCurrentSession()
			.createQuery("from ApplicationCriticality criticality order by id").list();
	}

	@Override
	public ApplicationCriticality retrieveById(int id) {
		return (ApplicationCriticality) sessionFactory.getCurrentSession().get(
				ApplicationCriticality.class, id);
	}

	@Override
	public ApplicationCriticality retrieveByName(String name) {
		return (ApplicationCriticality) sessionFactory.getCurrentSession()
				.createQuery("from ApplicationCriticality criticality where " +
						"criticality.name = :name").setString("name", name)
				.uniqueResult();
	}

}
