package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;

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
													.addOrder(Order.asc("createdDate")).list());
	}
	
	public ScanQueueTask retrieveById(int scanQueueTaskId) {
		ScanQueueTask retVal = (ScanQueueTask)sessionFactory.getCurrentSession()
							.createCriteria(ScanQueueTask.class)
							.add(Restrictions.eq("id", scanQueueTaskId)).uniqueResult();
		return(retVal);
	}
}
