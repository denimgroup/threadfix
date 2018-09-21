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
import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Hibernate SecurityEvent DAO implementation. Most basic methods are
 * implemented in the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractNamedObjectDao
 */
@Repository
public class HibernateSecurityEventDao
        extends AbstractNamedObjectDao<SecurityEvent>
        implements SecurityEventDao {

	@Autowired
	public HibernateSecurityEventDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    protected Order getOrder() {
        return Order.asc("name");
    }

    @Override
	public SecurityEvent retrieveByNativeIdAndWafId(String nativeId, String wafId) {
		return (SecurityEvent) sessionFactory.getCurrentSession()
			.createQuery("from SecurityEvent securityEvent where securityEvent.nativeId = :nativeId " +
					"and securityEvent.wafRule.waf = :wafId")
			.setString("nativeId", nativeId).setString("wafId", wafId).uniqueResult();
	}

    @Override
    protected Class<SecurityEvent> getClassReference() {
        return SecurityEvent.class;
    }


}
