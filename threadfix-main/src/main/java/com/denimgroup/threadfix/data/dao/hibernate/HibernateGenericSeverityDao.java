////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.GenericSeverity;

@Repository
public class HibernateGenericSeverityDao implements GenericSeverityDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateGenericSeverityDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<GenericSeverity> retrieveAll() {
		return getBaseCriteria().list();
	}

	@Override
	public GenericSeverity retrieveByName(String name) {
		return (GenericSeverity) getBaseCriteria().add(Restrictions.eq("name", name)).uniqueResult();
	}

	@Override
	public GenericSeverity retrieveById(int id) {
		return (GenericSeverity) getBaseCriteria().add(Restrictions.eq("id", id)).uniqueResult();
	}
	
	private Criteria getBaseCriteria() {
		return sessionFactory.getCurrentSession().createCriteria(GenericSeverity.class);
	}

    @Override
    public GenericSeverity retrieveByIntValue(int iValue) {
        return (GenericSeverity) getBaseCriteria().add(Restrictions.eq("intValue", iValue))
                .setMaxResults(1).uniqueResult();
    }
}
