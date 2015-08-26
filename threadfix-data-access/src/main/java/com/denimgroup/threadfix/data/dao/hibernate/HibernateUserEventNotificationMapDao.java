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
import com.denimgroup.threadfix.data.dao.UserEventNotificationMapDao;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.UserEventNotificationMap;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate UserEventNotificationMap DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 *
 * @author dshannon
 */
@Repository
public class HibernateUserEventNotificationMapDao
        extends AbstractObjectDao<UserEventNotificationMap>
        implements UserEventNotificationMapDao {

    @Autowired
    public HibernateUserEventNotificationMapDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<UserEventNotificationMap> getClassReference() {
        return UserEventNotificationMap.class;
    }

    @Override
    public void delete(UserEventNotificationMap userEventNotificationMap) {
        sessionFactory.getCurrentSession().delete(userEventNotificationMap);
    }

    @Override
    public List<UserEventNotificationMap> loadUserEventNotificationMaps(User user) {
        Criteria criteria = getSession().createCriteria(UserEventNotificationMap.class)
                .createAlias("user", "user")
                .add(Restrictions.eq("user", user));
        List<UserEventNotificationMap> userEventNotificationMaps = criteria.list();
        return userEventNotificationMaps;
    }
}
