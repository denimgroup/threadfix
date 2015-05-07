package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.ScheduledEmailReportDao;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;

@Repository
public class HibernateScheduledEmailReportDao extends HibernateScheduledJobDao<ScheduledEmailReport> implements ScheduledEmailReportDao {

	@Autowired
	public HibernateScheduledEmailReportDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Override
	protected Class<ScheduledEmailReport> getClassReference() {
		return ScheduledEmailReport.class;
	}
}
