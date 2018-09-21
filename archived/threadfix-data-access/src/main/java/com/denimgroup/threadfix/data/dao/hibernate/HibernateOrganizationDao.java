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
import com.denimgroup.threadfix.data.dao.OrganizationDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;

/**
 * Hibernate Organization DAO implementation. Most basic methods are implemented
 * in the AbstractNamedObjectDao
 * 
 * @author jraim
 * @see AbstractNamedObjectDao
 */
@Repository
public class HibernateOrganizationDao extends AbstractNamedObjectDao<Organization> implements OrganizationDao {

	@Autowired
	public HibernateOrganizationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
	}

    @Override
    protected Class<Organization> getClassReference() {
        return Organization.class;
    }


	@Override
	@SuppressWarnings("unchecked")
	public List<Organization> retrieveAllActiveFilter(Set<Integer> authenticatedTeamIds) {
		return sessionFactory.getCurrentSession()
				.createQuery("from Organization org where org.active = 1 and org.id in (:teams) order by org.name")
				.setParameterList("teams", authenticatedTeamIds).list();
	}

}
