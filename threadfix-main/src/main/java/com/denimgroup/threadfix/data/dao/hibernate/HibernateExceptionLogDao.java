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

import com.denimgroup.threadfix.data.dao.ExceptionLogDao;
import com.denimgroup.threadfix.data.entities.ExceptionLog;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 
 * @author mcollins
 */
@Repository
public class HibernateExceptionLogDao implements ExceptionLogDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateExceptionLogDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public void saveOrUpdate(ExceptionLog exceptionLog) {
		sessionFactory.getCurrentSession().saveOrUpdate(exceptionLog);
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<ExceptionLog> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from ExceptionLog log order by log.time desc")
                .setMaxResults(100)
				.list();
	}

}
