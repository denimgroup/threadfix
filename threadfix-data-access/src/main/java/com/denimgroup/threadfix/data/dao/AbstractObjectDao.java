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
package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.BaseEntity;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;

import java.util.List;

@SuppressWarnings("unchecked")
public abstract class AbstractObjectDao<T extends BaseEntity> implements GenericObjectDao<T> {

    protected SessionFactory sessionFactory;

    public static Integer MAX_IN_LIST_NUMBER = 1000;

    public AbstractObjectDao(SessionFactory sessionFactory) {
        assert sessionFactory != null : "SessionFactory was null, check your Spring configuration.";
        this.sessionFactory = sessionFactory;
    }

    @Override
    public T retrieveById(int id) {
        return (T) getSession().get(getClassReference(), id);
    }

    @Override
    public List<T> retrieveAllActive() {

        Criteria criteria = getSession()
                .createCriteria(getClassReference())
                .add(Restrictions.eq("active", true));

        Order order = getOrder();
        if (order != null) {
            criteria.addOrder(order);
        }

        return criteria.list();
    }

    @Override
    public List<T> retrieveAll() {
        Criteria criteria = getSession()
                .createCriteria(getClassReference());

        Order order = getOrder();
        if (order != null) {
            criteria.addOrder(order);
        }

        return criteria.list();
    }

    @Override
    public void saveOrUpdate(T object) {
        if (object.isNew()) {
            getSession().saveOrUpdate(object);
        } else {
            getSession().merge(object);
        }
    }

    public void insert(T object) {
        sessionFactory.openStatelessSession().insert(object);
    }



    protected Session getSession() {
        return sessionFactory.getCurrentSession();
    }

    protected abstract Class<T> getClassReference();

    protected Order getOrder() {
        return null;
    }

}
