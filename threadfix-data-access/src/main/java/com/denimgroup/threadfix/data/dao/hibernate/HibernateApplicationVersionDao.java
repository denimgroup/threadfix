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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ApplicationVersionDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationVersion;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.classic.Session;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

/**
 * 
 * @author stran
 * @see com.denimgroup.threadfix.data.dao.AbstractObjectDao
 */
@Repository
public class HibernateApplicationVersionDao extends AbstractObjectDao<ApplicationVersion> implements ApplicationVersionDao {

	@Autowired
	public HibernateApplicationVersionDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    protected Class<ApplicationVersion> getClassReference() {
        return ApplicationVersion.class;
    }

    @Override
    public Map<String, Object> getAllVersionsByAppId(List<Integer> appIds) {
        Session session = sessionFactory.getCurrentSession();
        Criteria criteria = session.createCriteria(Application.class);
        criteria.add(Restrictions.eq("active", true));
        criteria.createAlias("versions", "version");

        if (appIds != null)
            criteria.add(Restrictions.in("id", appIds));

        List<Application> applications = (List<Application>) criteria.list();
        Map<String, Object> map = CollectionUtils.map();
        for (Application application: applications) {
            map.put(application.getOrganization().getName() + " / " + application.getName(), application.getVersions());
        }

        return map;
    }

    @Override
    public ApplicationVersion loadAppVersionByName(String name, int appId) {
        return (ApplicationVersion) getVersionCriteria()
                .createAlias("application", "appAlias")
                .add(Restrictions.eq("appAlias.id", appId))
                .add(Restrictions.eq("name", name))
                .uniqueResult();
    }

    @Override
    public void delete(ApplicationVersion version) {
        sessionFactory.getCurrentSession().delete(version);
    }

    private Criteria getVersionCriteria() {
        Criteria criteria = sessionFactory.getCurrentSession()
                .createCriteria(ApplicationVersion.class);

        return criteria;
    }

    @Override
    protected Order getOrder() {
        return Order.asc("name");
    }
}
