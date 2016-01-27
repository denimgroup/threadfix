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

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Repository
@Transactional
public class HibernateDefaultConfigurationDao
        extends AbstractObjectDao<DefaultConfiguration>
        implements DefaultConfigurationDao {
	
	@Autowired
	public HibernateDefaultConfigurationDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    protected Class<DefaultConfiguration> getClassReference() {
        return DefaultConfiguration.class;
    }

    @Override
	public void delete(DefaultConfiguration config) {
		sessionFactory.getCurrentSession().delete(config);
	}

    @Override
    @SuppressWarnings("unchecked")
    public List<DefaultConfiguration> retrieveAll() {
        return getSession().createQuery("from DefaultConfiguration").list();
    }
	

    @Override
    public DefaultConfiguration loadCurrentConfiguration() {
        DefaultConfiguration configuration;

        List<DefaultConfiguration> list = retrieveAll();
        if (list.size() == 0) {
            configuration = DefaultConfiguration.getInitialConfig();
        } else if (list.size() > 1) {
            DefaultConfiguration config = list.get(0);
            list.remove(0);
            for (DefaultConfiguration defaultConfig : list) {
                delete(defaultConfig);
            }
            configuration = config;
        } else {
            configuration = list.get(0);
        }

        return  configuration;

    }

}
