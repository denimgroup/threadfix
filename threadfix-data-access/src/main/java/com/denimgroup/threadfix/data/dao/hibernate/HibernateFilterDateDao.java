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

import com.denimgroup.threadfix.data.dao.AbstractNamedObjectDao;
import com.denimgroup.threadfix.data.dao.FilterDateDao;
import com.denimgroup.threadfix.data.dao.FilterJsonBlobDao;
import com.denimgroup.threadfix.data.entities.FilterDate;
import com.denimgroup.threadfix.data.entities.FilterJsonBlob;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class HibernateFilterDateDao extends AbstractNamedObjectDao<FilterDate> implements FilterDateDao {

    @Autowired
    public HibernateFilterDateDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Class<FilterDate> getClassReference() {
        return FilterDate.class;
    }

    @Override
    protected Order getOrder() {
        return Order.asc("name");
    }

    @Override
    public FilterDate retrieveByName(String name) {
        return (FilterDate) getSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("active", true))
                .add(Restrictions.eq("name", name))
                .uniqueResult();
    }
}
