package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.Criteria;
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
	public DefaultDefectProfile retrieveDefectProfileByName(String name, Integer defectTrackerId, Integer appId) {
		Criteria criteria = getSession().createCriteria(getClassReference());
		criteria.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("name", name));
		if (defectTrackerId != null) {
			criteria.add(Restrictions.eq("defectTracker.id", defectTrackerId));
		} else {
			criteria.add(Restrictions.isNull("defectTracker"));
		}
		if (appId != null) {
			criteria.add(Restrictions.eq("referenceApplication.id", appId));
		} else {
			criteria.add(Restrictions.isNull("referenceApplication"));
		}
		criteria.setMaxResults(1);
		return (DefaultDefectProfile) criteria.uniqueResult();
	}
}
