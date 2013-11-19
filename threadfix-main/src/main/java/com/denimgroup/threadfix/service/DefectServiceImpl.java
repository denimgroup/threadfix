////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectMetadata;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;

@Service
@Transactional(readOnly = false)
public class DefectServiceImpl implements DefectService {

	private DefectDao defectDao = null;
	private VulnerabilityDao vulnerabilityDao = null;
	private ApplicationService applicationService = null;

	private final SanitizedLogger log = new SanitizedLogger(DefectService.class);
	
	@Autowired
	public DefectServiceImpl(DefectDao defectDao,
			VulnerabilityDao vulnerabilityDao,
			ApplicationService applicationService) {
		this.defectDao = defectDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.applicationService = applicationService;
	}

	@Override
	public List<Defect> loadAll() {
		return defectDao.retrieveAll();
	}

	@Override
	public Defect loadDefect(int defectId) {
		return defectDao.retrieveById(defectId);
	}

	@Override
	public Defect loadDefect(String nativeId) {
		return defectDao.retrieveByNativeId(nativeId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeDefect(Defect defect) {
		defectDao.saveOrUpdate(defect);
	}

	@Override
	@Transactional(readOnly = false)
	public Defect createDefect(List<Vulnerability> allVulns, String summary,
			String preamble, String component, String version,
			String severity, String priority, String status) {
		if (allVulns == null || allVulns.size() == 0 || allVulns.get(0) == null ||
				allVulns.get(0).getApplication() == null) {
			log.warn("Null input, exiting.");
			return null;
		}
		
		Vulnerability vuln = allVulns.get(0);

		Application application = vuln.getApplication();
		
		if (application != null) {
			applicationService.decryptCredentials(application);
		}
		
		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		if (dt == null) {
			log.warn("Unable to load Defect Tracker.");
			return null;
		}
		
		String editedSummary = summary, editedPreamble = preamble;

		// TODO handle error cases better.
		if (editedSummary == null || editedSummary.equals("")) {
			if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
				editedSummary = createMessage(vuln);
			} else {
				editedSummary = "No editedSummary could be parsed.";
			}
		}

		if (editedPreamble == null || editedPreamble.equals("")) {
			if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
				editedPreamble = createMessage(vuln);
			} else {
				editedPreamble = "No editedPreamble could be parsed.";
			}
		}

		List<Vulnerability> vulnsWithoutDefects = new ArrayList<>();

		for (Vulnerability vulnerability : allVulns) {
			if (vulnerability.getDefect() == null) {
				vulnsWithoutDefects.add(vulnerability);
			}
		}

		if (vulnsWithoutDefects.size() == 0) {
			log.warn("All the vulnerabilities already had defects, exiting.");
			return null;
		}
		
		String defectTrackerName = null;
		if (application != null && application.getDefectTracker() != null
				&& application.getDefectTracker().getDefectTrackerType() != null
				&& application.getDefectTracker().getDefectTrackerType().getName() != null) {
			defectTrackerName = application.getDefectTracker().getDefectTrackerType().getName();
		}
		
		if (defectTrackerName != null) {
			log.info("About to submit a defect to " + defectTrackerName + ".");
		} else {
			log.info("About to submit a defect to the defect tracker.");
		}
		
		String defectId = dt.createDefect(vulnsWithoutDefects,
				new DefectMetadata(editedSummary, editedPreamble,
				component, version, severity, priority, status));

		if (defectId != null) {
			
			Defect defect = new Defect();
			defect.setNativeId(defectId);
			defect.setVulnerabilities(vulnsWithoutDefects);
			defect.setApplication(application);
			defect.setStatus(status);
			defect.setDefectURL(dt.getBugURL(
					application.getDefectTracker().getUrl(), defectId));
			defectDao.saveOrUpdate(defect);

			for (Vulnerability vulnerability : vulnsWithoutDefects) {
				vulnerability.setDefect(defect);
				vulnerability.setDefectSubmittedTime(Calendar.getInstance());
				vulnerabilityDao.saveOrUpdate(vulnerability);
			}
			
			if (defectTrackerName != null) {
				log.info("Successfully submitted defect to " + defectTrackerName + ".");
			} else {
				log.info("Successfully submitted defect.");
			}
			return defect;
		}
		
		if (defectTrackerName != null) {
			log.warn("There was an error submitting the defect to " + defectTrackerName + ".");
		} else {
			log.warn("There was an error submitting the defect.");
		}
		return null;
	}

	private String createMessage(Vulnerability vuln) {
		if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
			return vuln.getGenericVulnerability().getName() + " at "
					+ vuln.getSurfaceLocation().getPath();
		} else {
			return "";
		}
	}

	// TODO make these error messages better
	@Override
	public String getErrorMessage(List<Vulnerability> vulns) {
		String noVulnsError = "No vulnerabilities were passed.";
		String noDefectTrackerError = "No defect tracker could be found - " +
				"check to see that you have entered your information.";
		String allVulnsAlreadyInSystem = "All the vulnerabilities were already in the system.";
		String defaultTrackerError = "There was an error connecting with the tracking system.";

		if (vulns == null || vulns.size() == 0) {
			return noVulnsError;
		}

		Vulnerability vuln = vulns.get(0);
		if (vuln == null || vuln.getApplication() == null) {
			return noDefectTrackerError;
		}

		Application application = vuln.getApplication();
		
		if (application != null) {
			applicationService.decryptCredentials(application);
		}
		
		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		if (dt == null) {
			return noDefectTrackerError;
		}

		List<Vulnerability> vulnList = new ArrayList<>();
		
		for (Vulnerability vulnerability : vulns) {
			if (vulnerability.getDefect() == null) {
				vulnList.add(vulnerability);
			}
		}

		if (vulnList.size() == 0) {
			return allVulnsAlreadyInSystem;
		}

		String trackerError = dt.getTrackerError();

		if (trackerError == null || trackerError.trim().equals("")) {
			return defaultTrackerError;
		} else {
			return trackerError;
		}
	}

	@Override
	@Transactional(readOnly = false)
	public boolean updateVulnsFromDefectTracker(Integer appId) {
		
		Application application = applicationService.loadApplication(appId);
		
		int numUpdated = 0;
		
		if (application == null) {
			log.warn("Application wasn't found, exiting.");
			return false;
		}
		
        applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		if (dt == null) {
			log.warn("Unable to load Defect Tracker, exiting.");
			return false;
		}
		
		if (application.getDefectList() == null ||
				application.getDefectList().size() == 0) {
			log.warn("No Defects found, updating information is " +
					"only useful after creating Defects. Exiting.");
			return false;
		}

		Map<Defect, Boolean> defectMap = dt.getMultipleDefectStatus(
				application.getDefectList());
		if (defectMap == null) {
			log.warn("There was an error retrieving information from the " +
					"Defect Tracker, exiting.");
			return false;
		}

		log.info("About to update vulnerability information from the defect tracker.");
		
		for (Defect defect : defectMap.keySet()) {
			if (defect != null && defect.getVulnerabilities() != null
					&& defectMap.containsKey(defect)) {
				for (Vulnerability vuln : defect.getVulnerabilities()) {
					Boolean defectOpenStatus = defectMap.get(defect);

					if (vuln.isActive() && defectOpenStatus != null &&
							!defectOpenStatus.booleanValue()) {
						if (vuln.getDefectClosedTime() == null) {
							vuln.setDefectClosedTime(Calendar.getInstance());
							vulnerabilityDao.saveOrUpdate(vuln);
							numUpdated += 1;
						}
					}
				}
			}
		}
		
		if (numUpdated == 0) {
			log.info("No vulnerabilities were updated. " +
					"This could just mean that no issues were closed.");
		} else {
			log.info("Updated information for " + numUpdated + " vulnerabilities.");
		}
		
		return true;
	}

	@Override
	public void deleteByDefectTrackerId(Integer defectTrackerId) {
		log.info("Deleting Defects connected to the Defect Tracker with the ID " + defectTrackerId);
		defectDao.deleteByDefectTrackerId(defectTrackerId);
	}

	@Override
	public void deleteByApplicationId(Integer applicationId) {
		log.info("Deleting Defects connected to the Application with the ID " + applicationId);
		defectDao.deleteByApplicationId(applicationId);
	}

	@Override
	public boolean mergeDefect(List<Vulnerability> vulnerabilities, String id) {
		
		if (vulnerabilities == null || vulnerabilities.size() == 0 || vulnerabilities.get(0) == null ||
				vulnerabilities.get(0).getApplication() == null) {
			log.warn("Null input, exiting.");
			return false;
		}
		
		Vulnerability vuln = vulnerabilities.get(0);

		Application application = vuln.getApplication();

        if (application == null) {
            return false;
        }

        applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		if (dt == null) {
			log.warn("Unable to load Defect Tracker.");
			return false;
		}
		Defect defect = new Defect();
		defect.setNativeId(id);
		defect.setDefectURL(dt.getBugURL(
				application.getDefectTracker().getUrl(), id));
		defect.setApplication(application);
		List<Defect> defectList = new ArrayList<>();
		defectList.add(defect);
		dt.getMultipleDefectStatus(defectList);
		defectDao.saveOrUpdate(defect);

		for (Vulnerability vulnerability : vulnerabilities) {
			vulnerability.setDefect(defect);
			vulnerability.setDefectSubmittedTime(Calendar.getInstance());
			vulnerabilityDao.saveOrUpdate(vulnerability);
		}

		log.info("Successfully merged vulns to Defect ID" + id + ".");

		return true;
	}
}