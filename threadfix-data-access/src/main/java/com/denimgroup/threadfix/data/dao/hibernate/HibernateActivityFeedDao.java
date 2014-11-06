////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.dao.ActivityFeedDao;
import com.denimgroup.threadfix.data.entities.ActivityFeed;
import com.denimgroup.threadfix.data.enums.ActivityFeedTypeName;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by mac on 11/6/14.
 */
@Repository
public class HibernateActivityFeedDao extends AbstractObjectDao<ActivityFeed> implements ActivityFeedDao {

    @Autowired
    public HibernateActivityFeedDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<ActivityFeed> getClassReference() {
        return ActivityFeed.class;
    }

    @Override
    public ActivityFeed retrieveByTypeAndObjectId(ActivityFeedTypeName type, int id) {

        Criteria criteria =
                sessionFactory.getCurrentSession()
                        .createCriteria(ActivityFeed.class)
                        .createAlias("activityFeedType", "type")
                        .add(Restrictions.eq("type.name", type.getName()))
                        .add(Restrictions.eq("objectId", (long) id));
        return (ActivityFeed) criteria.uniqueResult();
    }
}
