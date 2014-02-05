package com.denimgroup.threadfix.importer.dao;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
public class HibernateDefaultConfigurationDao implements DefaultConfigurationDao {
	
	private SessionFactory sessionFactory;

	@Autowired
	public HibernateDefaultConfigurationDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
 
	@SuppressWarnings("unchecked")
	@Override
	public List<DefaultConfiguration> retrieveAll() {
		return (List<DefaultConfiguration>) sessionFactory.getCurrentSession()
				.createCriteria(DefaultConfiguration.class)
				.addOrder(Order.asc("id"))
				.list();
	}
	
	@Override
	public void saveOrUpdate(DefaultConfiguration config) {
		if (config != null && config.getId() != null) {
			sessionFactory.getCurrentSession().merge(config);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(config);
		}
	}

	@Override
	public void delete(DefaultConfiguration config) {
		sessionFactory.getCurrentSession().delete(config);
	}
	
}
