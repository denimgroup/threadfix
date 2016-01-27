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
import com.denimgroup.threadfix.data.dao.EndpointPermissionDao;
import com.denimgroup.threadfix.data.entities.EndpointPermission;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Created by mcollins on 3/31/15.
 */
@Repository
public class HibernateEndpointPermissionDao
        extends AbstractNamedObjectDao<EndpointPermission>
        implements EndpointPermissionDao {

        @Autowired
        public HibernateEndpointPermissionDao(SessionFactory sessionFactory) {
                super(sessionFactory);
        }

        @Override
        public Class<EndpointPermission> getClassReference() {
                return EndpointPermission.class;
        }

        @Override
        public EndpointPermission retrieveByNameAndApplication(String stringPermission, Integer applicationId) {
                return (EndpointPermission) sessionFactory.getCurrentSession()
                        .createCriteria(EndpointPermission.class)
                        .add(Restrictions.eq("name", stringPermission))
                        .add(Restrictions.eq("application.id", applicationId))
                        .uniqueResult();
        }
}
