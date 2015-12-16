////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.AbstractNamedObjectDao;
import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class HibernateGenericSeverityDao
		extends AbstractNamedObjectDao<GenericSeverity>
		implements GenericSeverityDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateGenericSeverityDao(SessionFactory sessionFactory) {
		super(sessionFactory);
		this.sessionFactory = sessionFactory;
	}

	@Override
	protected Class<GenericSeverity> getClassReference() {
		return GenericSeverity.class;
	}

	@Override
    public GenericSeverity retrieveByIntValue(int iValue) {
		return (GenericSeverity) sessionFactory.getCurrentSession()
				.createCriteria(GenericSeverity.class)
				.add(Restrictions.eq("intValue", iValue))
                .setMaxResults(1).uniqueResult();
    }

	@Override
	public boolean doesCustomNameExist(String customName, int severityId){
		return !sessionFactory.getCurrentSession()
				.createCriteria(GenericSeverity.class)
				.add(Restrictions.ne("id",severityId))
				.add(Restrictions.or(Restrictions.eq("customName", customName),Restrictions.eq("name",customName)))
				.list().isEmpty();
	}
}
