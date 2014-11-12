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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerDao;
import com.denimgroup.threadfix.data.dao.DefectTrackerTypeDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.interfaces.ProjectMetadataSource;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.util.List;

@Service
@Transactional(readOnly = false) // used to be true
public class DefectTrackerServiceImpl implements DefectTrackerService {

	private DefectTrackerDao defectTrackerDao = null;
	private DefectTrackerTypeDao defectTrackerTypeDao = null;
	private DefectDao defectDao = null;

	private final SanitizedLogger log = new SanitizedLogger("DefectTrackerService");
	
	@Autowired
	public DefectTrackerServiceImpl(DefectTrackerDao defectTrackerDao,
			DefectTrackerTypeDao defectTrackerTypeDao, DefectDao defectDao) {
		this.defectTrackerDao = defectTrackerDao;
		this.defectTrackerTypeDao = defectTrackerTypeDao;
		this.defectDao = defectDao;
	}

	@Override
	public List<DefectTracker> loadAllDefectTrackers() {
		return defectTrackerDao.retrieveAll();
	}

	@Override
	public DefectTracker loadDefectTracker(int defectId) {
		return defectTrackerDao.retrieveById(defectId);
	}

	@Override
	public DefectTracker loadDefectTracker(String name) {
		return defectTrackerDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeDefectTracker(DefectTracker defectTracker) {
		defectTrackerDao.saveOrUpdate(defectTracker);
	}

	@Override
	@Transactional(readOnly = false)
	public void deleteById(int defectTrackerId) {
		log.info("Deleting Defect tracker with ID " + defectTrackerId);
		
		defectDao.deleteByDefectTrackerId(defectTrackerId);
	
		DefectTracker tracker = defectTrackerDao.retrieveById(defectTrackerId);
		tracker.setActive(false);
		
		if (tracker.getApplications() != null && tracker.getApplications().size() > 0) {
			for (Application app : tracker.getApplications()) {
				log.info("Removing defect tracker and project credentials from " +
						"application with ID " + app.getId());
				app.setDefectTracker(null);
				app.setUserName(null);
				app.setPassword(null);
				app.setProjectId(null);
				app.setProjectName(null);
			}
		}
		
		tracker.setApplications(null);
		
		defectTrackerDao.saveOrUpdate(tracker);
	}

	@Override
	public List<DefectTrackerType> loadAllDefectTrackerTypes() {
		return defectTrackerTypeDao.retrieveAll();
	}

	@Override
	public DefectTrackerType loadDefectTrackerType(int defectId) {
		return defectTrackerTypeDao.retrieveById(defectId);
	}

    @Override
    public ProjectMetadata getProjectMetadata(ProjectMetadataSource tracker) {
        return tracker == null ? null : tracker.getProjectMetadata();
    }

	@Override
	public DefectTrackerType loadDefectTrackerType(String name) {
		return defectTrackerTypeDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeDefectTrackerType(DefectTrackerType defectTrackerType) {
		defectTrackerTypeDao.saveOrUpdate(defectTrackerType);
	}

	@Override
	public boolean checkUrl(DefectTracker defectTracker, BindingResult result) {
		if (defectTracker != null && defectTracker.getDefectTrackerType() != null &&
				defectTracker.getUrl() != null) {
			
			AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(
					defectTrackerTypeDao.retrieveById(defectTracker.getDefectTrackerType().getId()));
			
			if (tracker != null) {
				tracker.setUrl(defectTracker.getUrl());
				
				if (tracker.hasValidUrl()) {
					return true;
				} else if (tracker.getLastError() != null) {
					result.rejectValue("url", null, null, tracker.getLastError());
					return false;
				}
			}
		}
		
		return false;
	}
}