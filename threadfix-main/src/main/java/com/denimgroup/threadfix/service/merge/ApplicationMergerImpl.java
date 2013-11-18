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
package com.denimgroup.threadfix.service.merge;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.JobStatusService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Service
public class ApplicationMergerImpl implements ApplicationMerger {
	
	private ApplicationDao applicationDao;
	private ScanDao scanDao;
	private JobStatusService jobStatusService;
	
	@Autowired
	public ApplicationMergerImpl(ApplicationDao applicationDao,
			ScanDao scanDao,
			JobStatusService jobStatusService) {
		this.applicationDao = applicationDao;
		this.scanDao = scanDao;
		this.jobStatusService = jobStatusService;
	}
	
	private final static SanitizedLogger log = new SanitizedLogger(ApplicationMergerImpl.class);

	/**
	 * This method is in here to allow passing an application id when the application isn't already in the session.
	 */
	public void applicationMerge(Scan scan, int applicationId, Integer statusId) {
		applicationMerge(scan, applicationDao.retrieveById(applicationId), statusId);
	}

	/**
	 * This method does the actual vulnerability merging across the app.
	 */
	public void applicationMerge(Scan scan, Application application, Integer statusId) {
		if (application == null || application.getVulnerabilities() == null || scan == null || scan.getFindings() == null) {
			log.warn("There was insufficient data to perform an application merge.");
			return;
		}
		
		long timeNow = System.currentTimeMillis();
		
		long totalCount = 0;
		
		List<Vulnerability> vulns = application.getVulnerabilities();
		
		FindingMatcher matcher = new FindingMatcher(scan);
		
		VulnerabilityCache 
			oldGuesser = new VulnerabilityCache(vulns),
			newGuesser = new VulnerabilityCache();

		ScanStatisticsUpdater scanStatisticsUpdater = new ScanStatisticsUpdater(scan, scanDao, 
				jobStatusService, statusId);
		
		for (Finding finding : scan.getFindings()) {
			scanStatisticsUpdater.doFindingCountUpdate();
			
			boolean match = false;

			for (Vulnerability vuln : oldGuesser.getPossibilities(finding)) {
				totalCount++;
				match = matcher.doesMatch(finding, vuln);
				if (match) {
					scanStatisticsUpdater.addFindingToOldVulnUpdate(finding, vuln);
					VulnerabilityParser.addToVuln(vuln, finding);
					break;
				}
			}

			// if the generated vulnerability didn't match any that were in the
			// db, compare it to valid new vulns still in memory
			if (!match) {
				for (Vulnerability newVuln : newGuesser.getPossibilities(finding)) {
					totalCount++;
					match = matcher.doesMatch(finding, newVuln);
					if (match) {
						scanStatisticsUpdater.addFindingToInScanVulnUpdate(finding);
						VulnerabilityParser.addToVuln(newVuln, finding);
						break;
					}
				}
			}

			// if it wasn't found there either, we need to save it.
			// it gets counted as new if a vuln is successfully parsed.
			if (!match) {
				Vulnerability newVuln = VulnerabilityParser.parse(finding);
				scanStatisticsUpdater.addFindingToNewVulnUpdate(finding, newVuln);
				if (newVuln != null) {
					newGuesser.add(newVuln);
				}
			}
		}
		
		log.info("Did " + totalCount + " comparisons while merging.");
		log.info("Merging took " + (System.currentTimeMillis() - timeNow) + " ms.");
	}
}
