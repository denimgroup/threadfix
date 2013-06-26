package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationCriticalityDao;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;

@Service
@Transactional(readOnly = true)
public class ApplicationCriticalityServiceImpl implements ApplicationCriticalityService {

	private ApplicationCriticalityDao applicationCriticalityDao;
	
	@Autowired
	public ApplicationCriticalityServiceImpl(ApplicationCriticalityDao applicationCriticalityDao) {
		this.applicationCriticalityDao = applicationCriticalityDao;
	}
	
	@Override
	public List<ApplicationCriticality> loadAll() {
		return applicationCriticalityDao.retrieveAll();
	}

	@Override
	public ApplicationCriticality loadApplicationCriticality(
			int applicationCriticalityId) {
		return applicationCriticalityDao.retrieveById(applicationCriticalityId);
	}

	@Override
	public ApplicationCriticality loadApplicationCriticality(
			String applicationCriticalityName) {
		return applicationCriticalityDao.retrieveByName(applicationCriticalityName);
	}

}
