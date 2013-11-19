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

import java.io.File;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.plugin.scanner.ChannelImporterFactory;
import com.denimgroup.threadfix.plugin.scanner.service.channel.ChannelImporter;
import com.denimgroup.threadfix.service.merge.FindingMatcher;
import com.denimgroup.threadfix.service.merge.ScanMerger;

// TODO figure out this Transactional stuff
// TODO reorganize methods - not in a very good order right now.
@Service
@Transactional(readOnly = false)
public class ScanMergeServiceImpl implements ScanMergeService {

	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");
	
	private ScanDao scanDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private UserDao userDao = null;
	private JobStatusService jobStatusService = null;
	private ScanMerger scanMerger = null;
	private VulnerabilityFilterService vulnerabilityFilterService = null;

	@Autowired
	public ScanMergeServiceImpl(ScanDao scanDao,
			ApplicationChannelDao applicationChannelDao,
			UserDao userDao,
			ScanMerger scanMerger,
			VulnerabilityFilterService vulnerabilityFilterService,
			JobStatusService jobStatusService) {
		this.scanDao = scanDao;
		this.applicationChannelDao = applicationChannelDao;
		this.userDao = userDao;
		this.vulnerabilityFilterService = vulnerabilityFilterService;
		this.jobStatusService = jobStatusService;
		this.scanMerger = scanMerger;
	}

	@Override
	public Scan saveRemoteScanAndRun(Integer channelId, String fileName) {
		if (channelId == null || fileName == null) {
			log.error("Unable to run RPC scan due to null input.");
			return null;
		}

		Scan scan = processScanFile(channelId, fileName, null);
		if (scan == null) {
			log.warn("The scan processing failed to produce a scan.");
			return null;
		}
		
		updateScanCounts(scan);
		vulnerabilityFilterService.updateVulnerabilities(scan);

		return scan;
	}

	@Override
	@Transactional(readOnly = false)
	public void updateSurfaceLocation(Application application) {
		if (application != null && application.getProjectRoot() != null
				&& application.getVulnerabilities() != null) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || vuln.getFindings() == null) {
					continue;
				}
				for (Finding finding : vuln.getFindings()) {
					if (finding == null) {
						continue;
					}
					String newPath = "";
//					StaticFindingPathUtils.getFindingPathWithRoot(finding,
//							application.getProjectRoot());
//					if (newPath == null)
//						continue;
					if (finding.getSurfaceLocation() != null) {
						finding.getSurfaceLocation().setPath(newPath);
					}
				}
			}
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void updateVulnerabilities(Application application) {
		List<Vulnerability> vulnerabilities = application.getVulnerabilities();
		
		FindingMatcher matcher = new FindingMatcher(null);

		if (vulnerabilities != null) {
			for (int i = 0; i < vulnerabilities.size(); i++) {
				if (vulnerabilities.get(i).getFindings() != null
						&& vulnerabilities.get(i).getFindings().size() > 0) {
					Finding finding = vulnerabilities.get(i).getFindings()
							.get(0);
					for (int j = i + 1; j < vulnerabilities.size(); j++) {
						if (matcher.doesMatch(finding, vulnerabilities.get(j))) {

							for (Finding vulnFinding : vulnerabilities.get(j)
									.getFindings()) {
								vulnerabilities.get(i).getFindings()
										.add(vulnFinding);
								vulnFinding.setVulnerability(vulnerabilities
										.get(i));
							}
							// set the matched vulnerability inactive, not a
							// good method, but deleting it will cause cascading
							// problems
							vulnerabilities.get(j).setActive(false);
						}
					}
				}
			}
		}
	}

	@Override
	public boolean processScan(Integer channelId, String fileName) {
		return processScan(channelId, fileName, null, null);
	}

	@Override
	public boolean processScan(Integer channelId, String fileName,
			Integer statusId, String userName) {
				
		if (channelId == null || fileName == null) {
			log.error("processScan() received null input and was unable to finish.");
			return false;
		}

		Scan scan = processScanFile(channelId, fileName, statusId);
		if (scan == null) {
			log.warn("processScanFile() failed to return a scan.");
			return false;
		}
		
		if (userName != null) {
			User user = userDao.retrieveByName(userName);
			scan.setUser(user);
		}
		
		scanDao.saveOrUpdate(scan);
		
		updateScanCounts(scan);
		vulnerabilityFilterService.updateVulnerabilities(scan);
		
		return true;
	}

	/**
	 * This is now just a wrapper around mergeScan. Let's perhaps remove it.
	 */
	@Override
	public Scan processRemoteScan(Scan scan) {
	
		if (scan == null) {
			log.warn("The remote import failed.");
			return null;
		}
	
		scanMerger.merge(scan, scan.getApplicationChannel());
	
		return scan;
	}
	
	private Scan processScanFile(Integer channelId, String fileName,
			Integer statusId) {
		if (channelId == null || fileName == null) {
			log.error("processScanFile() received null input and was unable to finish.");
			return null;
		}
	
		File file = new File(fileName);
		ApplicationChannel applicationChannel = applicationChannelDao
				.retrieveById(channelId);
	
		if (applicationChannel == null
				|| applicationChannel.getChannelType() == null
				|| !file.exists()) {
			log.warn("Invalid Application Channel, unable to find a ChannelImporter implementation.");
			return null;
		}
	
		// pick the appropriate parser
		ChannelImporter importer = ChannelImporterFactory.getChannelImporter(applicationChannel);
	
		if (importer == null) {
			log.warn("Unable to find suitable ChannelImporter implementation for "
					+ applicationChannel.getChannelType().getName()
					+ ". Returning null.");
			return null;
		}
	
		updateJobStatus(statusId, "Parsing findings from " +
				applicationChannel.getChannelType().getName() + " scan file.");
		log.info("Processing file " + fileName + " on channel "
				+ applicationChannel.getChannelType().getName() + ".");
	
		importer.setFileName(fileName);
		
		Scan scan = importer.parseInput();
		
		if (scan == null) {
			log.warn("The " + applicationChannel.getChannelType().getName()
					+ " import failed for file " + fileName + ".");
			return null;
		}
	
		updateJobStatus(statusId, "Findings successfully parsed, starting channel merge.");
		
		scanMerger.merge(scan, applicationChannel);
		
		vulnerabilityFilterService.updateVulnerabilities(
				applicationChannel.getApplication().getOrganization().getId(),
				applicationChannel.getApplication().getId());
		
		importer.deleteScanFile();
		return scan;
	}

	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}
	
	public void updateScanCounts(Scan scan) {
		Map<String, Object> mapMap = scanDao.getMapSeverityMap(scan);
		Map<String, Object> findingMap = scanDao.getFindingSeverityMap(scan);
		if (mapMap.get("id").equals(scan.getId()) && mapMap.get("id").equals(scan.getId())) {
			scan.setNumberInfoVulnerabilities((Long)mapMap.get("info") + (Long)findingMap.get("info"));
			scan.setNumberLowVulnerabilities((Long)mapMap.get("low") + (Long)findingMap.get("low"));
			scan.setNumberMediumVulnerabilities((Long)mapMap.get("medium") + (Long)findingMap.get("medium"));
			scan.setNumberHighVulnerabilities((Long)mapMap.get("high") + (Long)findingMap.get("high"));
			scan.setNumberCriticalVulnerabilities((Long)mapMap.get("critical") + (Long)findingMap.get("critical"));
			scanDao.saveOrUpdate(scan);
		} else {
			log.warn("ID from the database didn't match the scan ID, counts will not be added to the scan.");
		}
	}
}
