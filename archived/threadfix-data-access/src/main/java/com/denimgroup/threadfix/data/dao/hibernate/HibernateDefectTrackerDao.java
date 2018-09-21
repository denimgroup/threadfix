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
import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate DefectTracker DAO implementation. Most basic methods are
 * implemented in the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractNamedObjectDao
 */
@Repository
public class HibernateDefectTrackerDao
        extends AbstractNamedObjectDao<DefectTracker>
        implements DefectTrackerDao {

	@Autowired
	public HibernateDefectTrackerDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Override
	public DefectTracker retrieveByName(String name) {
		return (DefectTracker) getActiveDTCriteria()
				.add(Restrictions.eq("name", name))
				.uniqueResult();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<DefectTracker> retrieveAll() {
		return getActiveDTCriteria().createAlias("defectTrackerType", "dtt")
									.addOrder(Order.asc("dtt.name"))
									.addOrder(Order.asc("name"))
									.list();
	}

	private Criteria getActiveDTCriteria() {
		return sessionFactory.getCurrentSession()
				   			 .createCriteria(DefectTracker.class)
				   			 .add(Restrictions.eq("active", true));
	}

    @Override
    protected Class<DefectTracker> getClassReference() {
        return DefectTracker.class;
    }
}
