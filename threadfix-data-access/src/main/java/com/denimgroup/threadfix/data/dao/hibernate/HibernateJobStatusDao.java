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
import com.denimgroup.threadfix.data.dao.JobStatusDao;
import com.denimgroup.threadfix.data.entities.JobStatus;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate JobStatus DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractObjectDao
 */
@Repository
public class HibernateJobStatusDao
        extends AbstractObjectDao<JobStatus>
        implements JobStatusDao {

	@Autowired
	public HibernateJobStatusDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    protected Order getOrder() {
        return Order.desc("modifiedDate");
    }

    @SuppressWarnings("unchecked")
	@Override
	public List<JobStatus> retrieveAllOpen() {
		return sessionFactory
				.getCurrentSession()
				.createQuery(
                        "from JobStatus jobStatus where jobStatus.open = :open "
                                + "order by jobStatus.modifiedDate desc").setBoolean("open", true)
				.list();
	}


    @Override
    protected Class<JobStatus> getClassReference() {
        return JobStatus.class;
    }

    @Override
	public void evict(JobStatus status) {
		 sessionFactory.getCurrentSession().evict(status);
	}

}
