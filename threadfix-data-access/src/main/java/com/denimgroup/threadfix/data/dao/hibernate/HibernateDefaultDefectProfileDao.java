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
