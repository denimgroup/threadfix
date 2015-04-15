////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.IllegalStateRestException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.service.DefectDescriptionBuilder.makeDescription;

@Service
@Transactional(readOnly = false)
public class DefectServiceImpl implements DefectService {

    @Autowired
	private DefectDao defectDao;
	@Autowired
	private VulnerabilityDao vulnerabilityDao;
	@Autowired
	private ApplicationService applicationService;
    @Autowired
    private DefectSubmissionServiceImpl defectSubmissionService;
	@Autowired
	private ApplicationDao applicationDao;

	private final SanitizedLogger log = new SanitizedLogger(DefectService.class);

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

    private String getAdditionalScannerInfo(List<Vulnerability> allVulns) {

        for (Vulnerability vuln : allVulns) {
            for (Finding finding: vuln.getFindings()){
                String scannerDetail = finding.getScannerDetail();
                if(scannerDetail != null && !scannerDetail.equals("")){
                    return scannerDetail;
                }
            }
        }

        return "";
    }

	@Override
	@Transactional(readOnly = false)
	public Map<String, Object> createDefect(List<Vulnerability> allVulns,
            String summary, String preamble, String component, String version,
			String severity, String priority, String status, Map<String,
            Object> fieldsMap, Boolean additionalScannerInfo) {
		if (allVulns == null || allVulns.size() == 0 || allVulns.get(0) == null ||
				allVulns.get(0).getApplication() == null) {
			log.warn("Null input, exiting.");
			return null;
		}

        Map<String, Object> map = new HashMap<>();
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

                if(additionalScannerInfo != null && additionalScannerInfo){
                    String additionalScannerInfoStr = getAdditionalScannerInfo(allVulns);

                    if(additionalScannerInfoStr == null || additionalScannerInfoStr.equals("")){
                        editedPreamble = createMessage(vuln);
                    } else  {
                        editedPreamble = createMessageWithScannerInfo(vuln, additionalScannerInfoStr);
                    }
                } else {
                    editedPreamble = createMessage(vuln);
                }
			} else {
				editedPreamble = "No editedPreamble could be parsed.";
			}
		}

		List<Vulnerability> vulnsWithoutDefects = list();

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

        DefectMetadata metadata = new DefectMetadata(editedSummary, editedPreamble,
                component, version, severity, priority, status, fieldsMap);

        String description = makeDescription(vulnsWithoutDefects, metadata);
        metadata.setFullDescription(description);

        String defectId = defectSubmissionService.submitDefect(dt, vulnsWithoutDefects, metadata);

		if (defectId != null) {

			Defect defect = new Defect();
			defect.setNativeId(defectId);
			defect.setVulnerabilities(vulnsWithoutDefects);
			defect.setApplication(application);
            Object sObj = null;
            if (fieldsMap != null && status == null) {
                sObj = fieldsMap.get("status")==null ? fieldsMap.get("Status") : fieldsMap.get("status");
            }
			status = (sObj != null ? String.valueOf(sObj) : status);

            // By default, set status to Open
            if (status == null) {
                status = "Open";
            }

            defect.setStatus(status);
			defect.setDefectURL(dt.getBugURL(application.getDefectTracker().getUrl(), defectId));
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
            map.put(DEFECT, defect);
			return map;
		}

		if (defectTrackerName != null) {
			log.warn("There was an error submitting the defect to " + defectTrackerName + ".");
		} else {
			log.warn("There was an error submitting the defect.");
		}
        map.put(ERROR, dt.getLastError());
		return map;
	}

    private String createMessageWithScannerInfo(Vulnerability vuln, String scannerInfo) {

        String message = scannerInfo;

        if (vuln.getGenericVulnerability() != null && vuln.getSurfaceLocation() != null) {
            message += "\n" + vuln.getGenericVulnerability().getName() + " at "
                    + vuln.getSurfaceLocation().getPath();
        }

        return message;
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

        applicationService.decryptCredentials(application);

        AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		if (dt == null) {
			return noDefectTrackerError;
		}

		List<Vulnerability> vulnList = list();
		
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
							!defectOpenStatus) {
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
		List<Defect> defectList = list();
		defectList.add(defect);
        Map<Defect, Boolean> map = dt.getMultipleDefectStatus(defectList);
        if (map.isEmpty())
            return false;
		defectDao.saveOrUpdate(defect);

		for (Vulnerability vulnerability : vulnerabilities) {
			vulnerability.setDefect(defect);
			vulnerability.setDefectSubmittedTime(Calendar.getInstance());
			vulnerabilityDao.saveOrUpdate(vulnerability);
		}

		log.info("Successfully added vulns to Defect ID " + id + ".");

		return true;
	}

	@Override
	public void updateScannerSuppliedStatuses(int appId) {

		Application application = applicationDao.retrieveById(appId);

		if (application == null) {
			log.error("Somehow updateScannerSuppliedStatuses was called with an invalid application ID. Throwing exception.");
			throw new IllegalStateRestException("Unable to find an application with ID " + appId);
		}

		if (application.getDefectTracker() == null) {
			log.debug("In updateScannerSuppliedStatuses but didn't have a Defect Tracker attached.");
			return;
		}

		boolean needsUpdate = setDefectIdsFromScanners(application);

		if (needsUpdate) {
			log.debug("Created new defects, getting status updates from the server.");
			updateVulnsFromDefectTracker(appId);
		} else {
			log.debug("Didn't find any scanner-supplied defect IDs, exiting.");
		}
	}

	// TODO a simple hql query could make this much faster
	// from finding where issueid != null and issueid.vuln.app = application
	public boolean setDefectIdsFromScanners(@Nonnull Application application) {

		boolean hadAnyStatuses = false;
		AbstractDefectTracker tracker = DefectTrackerFactory.getTracker(application);

		if (tracker != null && application.getVulnerabilities() != null) {
			for (Vulnerability vulnerability : application.getVulnerabilities()) {
				for (Finding finding : vulnerability.getFindings()) {
					String issueId = finding.getIssueId();
					if (issueId != null) {
						Defect defect = new Defect();
						defect.setNativeId(issueId);
						log.debug("Creating new Defect with ID " + issueId + " for vulnerability with ID " + vulnerability.getId());

						String url = application.getDefectTracker().getUrl();
						defect.setDefectURL(tracker.getBugURL(url, issueId));
						defect.setVulnerabilities(list(vulnerability));
						defect.setStatus("Open");
						defect.setApplication(application);

						vulnerability.setDefect(defect);

						hadAnyStatuses = true;
						defectDao.saveOrUpdate(defect);
						vulnerabilityDao.saveOrUpdate(vulnerability);
					}
				}
			}
		}

		return hadAnyStatuses;
	}
}