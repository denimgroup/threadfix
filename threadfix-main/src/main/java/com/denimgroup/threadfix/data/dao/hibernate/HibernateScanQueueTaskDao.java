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
import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.ScanQueueTask.ScanQueueTaskStatus;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class HibernateScanQueueTaskDao
        extends AbstractObjectDao<ScanQueueTask>
        implements ScanQueueTaskDao{
	
	@Autowired
	public HibernateScanQueueTaskDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    protected Class<ScanQueueTask> getClassReference() {
        return ScanQueueTask.class;
    }

    @Override
    protected Order getOrder() {
        return Order.asc("createdDate");
    }

    @SuppressWarnings("unchecked")
	@Override
	public List<ScanQueueTask> retrieveAvailable() {
		return(sessionFactory.getCurrentSession().createCriteria(ScanQueueTask.class)
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("status",  ScanQueueTaskStatus.STATUS_QUEUED.getValue()))
				.addOrder(Order.asc("createdDate")).list());
	}

	@Override
	public void delete(ScanQueueTask task) {
		sessionFactory.getCurrentSession().delete(task);
	}
}
