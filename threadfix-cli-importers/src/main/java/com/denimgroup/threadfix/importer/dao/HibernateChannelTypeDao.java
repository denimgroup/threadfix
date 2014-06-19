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
package com.denimgroup.threadfix.importer.dao;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class HibernateChannelTypeDao extends AbstractObjectDao<ChannelType> implements ChannelTypeDao {

    @Autowired
    public HibernateChannelTypeDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<ChannelType> retrieveAll() {
        return sessionFactory.getCurrentSession()
                .createQuery("from ChannelType channelType order by channelType.name").list();
    }

    @Override
    public ChannelType retrieveByName(String name) {
        return (ChannelType) sessionFactory.getCurrentSession()
                .createQuery("from ChannelType channelType where channelType.name = :name")
                .setString("name", name).uniqueResult();
    }

    @Override
    public Class<ChannelType> getClassReference() {
        return ChannelType.class;
    }
}
