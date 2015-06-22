package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
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
		DefaultDefectProfile defaultDefectProfile = retrieveById(defaultDefectProfileId);
		getSession().delete(defaultDefectProfile);
		getSession().flush();
	}

	@Override
	public DefaultDefectProfile retrieveDefectProfileByName(String name, Integer appId) {
		return (DefaultDefectProfile) getSession()
				.createCriteria(getClassReference())
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("name", name))
				.add(Restrictions.eq("referenceApplication.id", appId))
				.setMaxResults(1)
				.uniqueResult();
	}
}
