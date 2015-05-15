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

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.EventDao;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Event;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public class HibernateEventDao extends AbstractObjectDao<Event> implements EventDao {

    private SessionFactory sessionFactory;

    @Autowired
    public HibernateEventDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<Event> getClassReference() {
        return Event.class;
    }

    @Override
    public List<Event> retrieveAllByScan(Scan scan) {

        Criteria criteria = getSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("active", true))
                .add(Restrictions.eq("scan", scan));

        Order order = getOrder();
        if (order != null) {
            criteria.addOrder(order);
        }

        return criteria.list();
    }

    @Override
    public List<Event> retrieveAllByVulnerability(Vulnerability vulnerability) {

        Criteria criteria = getSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("active", true))
                .add(Restrictions.eq("vulnerability", vulnerability));

        Order order = getOrder();
        if (order != null) {
            criteria.addOrder(order);
        }

        return criteria.list();
    }

    @Override
    public List<Event> retrieveAllByDefect(Defect defect) {

        Criteria criteria = getSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("active", true))
                .add(Restrictions.eq("defect", defect));

        Order order = getOrder();
        if (order != null) {
            criteria.addOrder(order);
        }

        return criteria.list();
    }
}
