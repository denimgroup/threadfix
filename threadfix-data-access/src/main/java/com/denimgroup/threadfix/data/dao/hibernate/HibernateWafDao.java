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
import com.denimgroup.threadfix.data.dao.WafDao;
import com.denimgroup.threadfix.data.entities.Waf;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Hibernate Waf DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractNamedObjectDao
 */
@Repository
public class HibernateWafDao
        extends AbstractNamedObjectDao<Waf>
        implements WafDao {

    @Override
    protected Order getOrder() {
        return Order.asc("name");
    }

    @Autowired
    public HibernateWafDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Waf retrieveByName(String name) {
        return (Waf) getSession().createCriteria(Waf.class)
                .add(Restrictions.eq("name", name))
                .add(Restrictions.eq("active", true))
                .uniqueResult();
    }

    @Override
    protected Class<Waf> getClassReference() {
        return Waf.class;
    }
}
