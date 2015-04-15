package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.hibernate.classic.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.DefaultDefectProfileDao;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;

@Repository
public class HibernateDefaultDefectProfileDao extends
		AbstractObjectDao<DefaultDefectProfile> implements
		DefaultDefectProfileDao {

	@Autowired
	public HibernateDefaultDefectProfileDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Override
	protected Class<DefaultDefectProfile> getClassReference() {
		return DefaultDefectProfile.class;
	}

	@Override
	public void deleteById(int defaultDefectProfileId) {
		DefaultDefectProfile defaultDefectProfile = this.retrieveById(defaultDefectProfileId);
		Session session = this.sessionFactory.getCurrentSession();
		session.delete(defaultDefectProfile);
		session.flush();
	}
}
