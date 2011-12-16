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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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

	private final Log log = LogFactory.getLog(DefectService.class);
	
	@Autowired
	public DefectServiceImpl(DefectDao defectDao, VulnerabilityDao vulnerabilityDao) {
		this.defectDao = defectDao;
		this.vulnerabilityDao = vulnerabilityDao;
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
	public Defect createDefect(List<Vulnerability> allVulns, String summary, String preamble,
			String component, String version, String severity) {
		if (allVulns == null || allVulns.size() == 0 || allVulns.get(0) == null || 
				allVulns.get(0).getApplication() == null) {
			log.warn("Null input, exiting.");
			return null;
		}
		
		Vulnerability vuln = allVulns.get(0);

		Application application = vuln.getApplication();
		AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
		if (dt == null) {
			log.warn("Unable to load Defect Tracker.");
			return null;
		}

		// TODO handle error cases better.
		if (summary == null || summary.equals("")) {
			if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
				summary = createMessage(vuln);
			} else {
				summary = "No summary could be parsed.";
			}
		}

		if (preamble == null || preamble.equals("")) {
			if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
				preamble = createMessage(vuln);
			} else {
				preamble = "No preamble could be parsed.";
			}
		}

		List<Vulnerability> vulnsWithoutDefects = new ArrayList<Vulnerability>();

		for (Vulnerability vulnerability : allVulns)
			if (vulnerability.getDefect() == null)
				vulnsWithoutDefects.add(vulnerability);

		if (vulnsWithoutDefects.size() == 0) {
			log.warn("All the vulnerabilities already had defects, exiting.");
			return null;
		}
		
		String defectTrackerName = null;
		if (application != null && application.getDefectTracker() != null
				&& application.getDefectTracker().getDefectTrackerType() != null
				&& application.getDefectTracker().getDefectTrackerType().getName() != null)
			defectTrackerName = application.getDefectTracker().getDefectTrackerType().getName();
		
		if (defectTrackerName != null)
			log.info("About to submit a defect to " + defectTrackerName + ".");
		else
			log.info("About to submit a defect to the defect tracker.");
		
		String defectId = dt.createDefect(vulnsWithoutDefects, new DefectMetadata(summary, preamble,
				component, version, severity));

		if (defectId != null) {
			
			Defect defect = new Defect();
			defect.setNativeId(defectId);
			defect.setVulnerabilities(vulnsWithoutDefects);
			defect.setApplication(application);
			defectDao.saveOrUpdate(defect);

			for (Vulnerability vulnerability : vulnsWithoutDefects) {
				vulnerability.setDefect(defect);
				vulnerability.setDefectSubmittedTime(Calendar.getInstance());
				vulnerabilityDao.saveOrUpdate(vulnerability);
			}
			
			if (defectTrackerName != null)
				log.info("Successfully submitted defect to " + defectTrackerName + ".");
			else
				log.info("Successfully submitted defect.");
			return defect;
		}
		
		if (defectTrackerName != null)
			log.warn("There was an error submitting the defect to " + defectTrackerName + ".");
		else
			log.warn("There was an error submitting the defect.");
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
		String noDefectTrackerError = "No defect tracker could be found - check to see that you have entered your information.";
		String allVulnsAlreadyInSystem = "All the vulnerabilities were already in the system.";
		String defaultTrackerError = "There was an error connecting with the tracking system.";

		if (vulns == null || vulns.size() == 0)
			return noVulnsError;

		Vulnerability vuln = vulns.get(0);
		if (vuln == null || vuln.getApplication() == null)
			return noDefectTrackerError;

		Application application = vuln.getApplication();
		AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
		if (dt == null)
			return noDefectTrackerError;

		List<Vulnerability> vulnList = new ArrayList<Vulnerability>();
		
		for (Vulnerability vulnerability : vulns)
			if (vulnerability.getDefect() == null)
				vulnList.add(vulnerability);

		if (vulnList.size() == 0)
			return allVulnsAlreadyInSystem;

		String trackerError = dt.getTrackerError();

		if (trackerError == null || trackerError.trim().equals("")) {
			return defaultTrackerError;
		} else {
			return trackerError;
		}
	}

	@Override
	public String getDefectStatus(Vulnerability vuln) {
		String retVal = "";
		if (vuln == null || vuln.getDefect() == null || vuln.getApplication() == null) {
			return null;
		} else {
			Defect defect = vuln.getDefect();
			Application application = vuln.getApplication();
			AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
			retVal = dt.getStatus(defect);

			return retVal;
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void updateVulnsFromDefectTracker(Application application) {
		int numUpdated = 0;
		
		if (application == null) {
			log.warn("Application wasn't found, exiting.");
			return;
		}

		AbstractDefectTracker dt = new DefectTrackerFactory().getTracker(application);
		if (dt == null) {
			log.warn("Unable to load Defect Tracker, exiting.");
			return;
		}
		
		if (application.getDefectList() == null || application.getDefectList().size() == 0) {
			log.warn("No Defects found, updating information is only useful after creating Defects. Exiting.");
			return;
		}

		Map<Defect, Boolean> defectMap = dt.getMultipleDefectStatus(application.getDefectList());
		if (defectMap == null) {
			log.warn("There was an error retrieving information from the Defect Tracker, exiting.");
			return;
		}

		log.info("About to update vulnerability information from the defect tracker.");
		
		for (Defect defect : defectMap.keySet()) {
			if (defect != null && defect.getVulnerabilities() != null
					&& defectMap.containsKey(defect)) {
				for (Vulnerability vuln : defect.getVulnerabilities()) {
					Boolean defectOpenStatus = defectMap.get(defect);

					if (vuln.isActive() && defectOpenStatus != null && !defectOpenStatus.booleanValue()) {
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
			log.warn("No vulnerabilities were updated - check your configuration.");
		} else {
			log.info("Updated information for " + numUpdated + " vulnerabilities.");
		}
	}

	@Override
	public void deleteByDefectTrackerId(Integer defectTrackerId) {
		defectDao.deleteByDefectTrackerId(defectTrackerId);
	}

	@Override
	public void deleteByApplicationId(Integer applicationId) {
		defectDao.deleteByApplicationId(applicationId);
	}
}