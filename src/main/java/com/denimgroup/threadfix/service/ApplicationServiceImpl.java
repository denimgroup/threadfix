////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service;

import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;

@Service
@Transactional(readOnly = true)
public class ApplicationServiceImpl implements ApplicationService {

	private ApplicationDao applicationDao = null;
	private DefectTrackerDao defectTrackerDao = null;

	@Autowired
	public ApplicationServiceImpl(ApplicationDao applicationDao, DefectTrackerDao defectTrackerDao) {
		this.applicationDao = applicationDao;
		this.defectTrackerDao = defectTrackerDao;
	}

	@Override
	public List<Application> loadAll() {
		return applicationDao.retrieveAll();
	}

	@Override
	public List<Application> loadAllActive() {
		return applicationDao.retrieveAllActive();
	}

	@Override
	public Application loadApplication(int applicationId) {
		return applicationDao.retrieveById(applicationId);
	}

	@Override
	public Application loadApplication(String applicationName) {
		return applicationDao.retrieveByName(applicationName);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeApplication(Application application) {
		if (application != null)
			applicationDao.saveOrUpdate(application);
	}

	@Override
	@Transactional(readOnly = false)
	public void deleteById(int applicationId) {
		applicationDao.deleteById(applicationId);
	}

	@Override
	@Transactional(readOnly = false)
	public void deactivateApplication(Application application) {
		application.setActive(false);
		application.setModifiedDate(new Date());
		applicationDao.saveOrUpdate(application);
	}
	
	@Override
	public boolean validateApplicationDefectTracker(Application application, BindingResult result) {
		if (application == null || result == null)
			return false;
		
		if (application.getDefectTracker() != null && application.getDefectTracker().getId() == 0) {
			application.setDefectTracker(null);
			application.setUserName(null);
			application.setPassword(null);
		} else if (application.getDefectTracker() != null){
			DefectTracker defectTracker = defectTrackerDao.retrieveById(application.getDefectTracker().getId());
			if (defectTracker == null) {
				result.rejectValue("defectTracker.id", "errors.invalid", new String [] { "Defect Tracker choice" }, null);
				application.setUserName(null);
				application.setPassword(null);
				application.setProjectName(null);
			} else {
				application.setDefectTracker(defectTracker);
				AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
				if (dt != null) {
					if (application.getUserName() == null || application.getUserName().isEmpty())
						result.rejectValue("userName", "errors.required", new String [] { "User Name" }, null);
					if (application.getPassword() == null || application.getPassword().isEmpty())
						result.rejectValue("password", "errors.required", new String [] { "Password" }, null);
					
					if (!result.hasErrors()) { 
						if (!dt.hasValidCredentials()) {
							result.rejectValue("userName", "errors.invalid", new String [] { "User / password combination" }, null);
							application.setUserName(null);
							application.setPassword(null);
							application.setProjectName(null);
						} else if (!dt.hasValidProjectName()) {
							result.rejectValue("projectName", "errors.invalid", new String [] { "Project Name" }, null);
							application.setProjectName(null);
						} else {
							application.setProjectId(dt.getProjectIdByName());
							return checkNewDefectTracker(application);
						}
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * 
	 * @param application
	 * @return true if the application has a different defect tracker than the database version, 
	 * 		   false otherwise
	 */
	private boolean checkNewDefectTracker(Application application) {
		if (application == null || application.getId() == null || 
				application.getDefectTracker() == null || application.getDefectTracker().getId() == null)
			return false;
		
		Application databaseApplication = applicationDao.retrieveById(application.getId());
		
		if (databaseApplication == null || databaseApplication.getId() == null || 
				databaseApplication.getDefectTracker() == null || 
				databaseApplication.getDefectTracker().getId() == null)
			return false;
		
		return !application.getDefectTracker().getId().equals(databaseApplication.getDefectTracker().getId());
	}
}
