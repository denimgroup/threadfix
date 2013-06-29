package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ScanQueueTaskDao;
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
}
