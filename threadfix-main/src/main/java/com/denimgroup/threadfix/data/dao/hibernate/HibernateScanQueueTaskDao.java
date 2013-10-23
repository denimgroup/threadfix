package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.ScanQueueTask.ScanQueueTaskStatus;

@Repository
public class HibernateScanQueueTaskDao implements ScanQueueTaskDao{
	
	private SessionFactory sessionFactory;
	
	@Autowired
	public HibernateScanQueueTaskDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public void saveOrUpdate(ScanQueueTask scanQueueTask) {
		sessionFactory.getCurrentSession().saveOrUpdate(scanQueueTask);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<ScanQueueTask> retrieveAll() {
		return (sessionFactory.getCurrentSession().createCriteria(ScanQueueTask.class)
				.add(Restrictions.eq("active", true))
				.addOrder(Order.asc("createdDate")).list());
	}
	
	@Override
	public ScanQueueTask retrieveById(int scanQueueTaskId) {
		ScanQueueTask retVal = (ScanQueueTask)sessionFactory.getCurrentSession()
							.createCriteria(ScanQueueTask.class)
							.add(Restrictions.eq("id", scanQueueTaskId)).uniqueResult();
		return(retVal);
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
