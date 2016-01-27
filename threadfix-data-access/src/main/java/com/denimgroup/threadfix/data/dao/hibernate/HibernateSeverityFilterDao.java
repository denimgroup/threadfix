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
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.SeverityFilterDao;
import com.denimgroup.threadfix.data.entities.SeverityFilter;

import java.util.List;

@Repository
public class HibernateSeverityFilterDao implements SeverityFilterDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateSeverityFilterDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@Transactional
	public void saveOrUpdate(SeverityFilter severityFilter) {
		if (severityFilter != null && severityFilter.getId() != null) {
			sessionFactory.getCurrentSession().merge(severityFilter);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(severityFilter);
		}
	}

	@Override
	public SeverityFilter retrieveGlobal() {
		return (SeverityFilter) getBaseCriteria()
				.add(Restrictions.eq("global", true))
				.setMaxResults(1)
				.uniqueResult();
	}

	@Override
	public SeverityFilter retrieveTeam(int orgId) {
		return (SeverityFilter) getBaseCriteria()
				.add(Restrictions.eq("organization.id", orgId))
				.setMaxResults(1)
				.uniqueResult();
	}

	@Override
	public SeverityFilter retrieveApplication(int appId) {
		return (SeverityFilter) getBaseCriteria()
				.add(Restrictions.eq("application.id", appId))
				.setMaxResults(1)
				.uniqueResult();
	}

	@Override
	public List<SeverityFilter> retrieveAll() {
		return getBaseCriteria().list();
	}

	private Criteria getBaseCriteria() {
		return sessionFactory.getCurrentSession().createCriteria(SeverityFilter.class);
	}
	
}
