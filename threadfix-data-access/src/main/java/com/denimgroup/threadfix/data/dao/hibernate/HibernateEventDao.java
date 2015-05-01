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

import com.denimgroup.threadfix.data.dao.EventDao;
import com.denimgroup.threadfix.data.entities.Event;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.Date;

@Repository
public class HibernateEventDao implements EventDao {

    private SessionFactory sessionFactory;

    @Autowired
    public HibernateEventDao(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }
    
    @Override
    public void saveOrUpdate(Event event) {
        sessionFactory.getCurrentSession().save(event);
    }
    
    @Override
    public void delete(Event event) {
        event.setActive(false);
        event.setModifiedDate(new Date());
        saveOrUpdate(event);
    }
    
    
    @Override
    public Event retrieveById(int id) {
        return (Event)sessionFactory.getCurrentSession()
                .createCriteria(Event.class)
                .add(Restrictions.eq("id", id))
                .uniqueResult();
    }
    
    private Criteria getVulnCriteria(int number) {
        return sessionFactory.getCurrentSession()
                .createCriteria(Event.class)
                .add(Restrictions.eq("active", true))
                .addOrder(Order.desc("id"))
                .setMaxResults(number);
    }

}
