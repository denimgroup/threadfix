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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.merge.FindingMatcher;
import com.denimgroup.threadfix.service.merge.PermissionsHandler;
import com.denimgroup.threadfix.service.merge.ScanMerger;
import edu.emory.mathcs.backport.java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

// TODO figure out this Transactional stuff
// TODO reorganize methods - not in a very good order right now.
@Service
@Transactional(readOnly = false)
public class ScanMergeServiceImpl implements ScanMergeService {

	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");

	@Autowired
	private ScanDao scanDao;
	@Autowired
	private ApplicationChannelDao applicationChannelDao;
	@Autowired
	private UserDao userDao;
	@Autowired
	private JobStatusService jobStatusService;
	@Autowired
	private ScanMerger scanMerger;
	@Autowired
	private VulnerabilityFilterService vulnerabilityFilterService;
	@Autowired
	private VulnerabilityStatusService vulnerabilityStatusService;
	@Autowired
	private ChannelImporterFactory channelImporterFactory;
	@Autowired
	private VulnerabilityService vulnerabilityService;
	@Autowired
	private DefectService defectService;
	@Autowired
	private PermissionsHandler permissionsHandler;
	@Autowired
	private DefaultConfigService defaultConfigService;

	private Pattern scanFileRegex = Pattern.compile("(.*)(scan-file-[0-9]+-[0-9]+)");

	@Override
	public Scan saveRemoteScanAndRun(Integer channelId, List<String> fileNames, List<String> originalFileNames) {
		if(channelId == null || fileNames == null || fileNames.isEmpty()){
			log.error("Unable to run RPC scan due to null input.");
			return null;
		}

		Scan scan = processScanFiles(channelId, fileNames, originalFileNames, null);

		if (scan == null) {
			log.warn("The scan processing failed to produce a scan.");
			return null;
		}

		Integer id = scan.getApplication().getId();
		defectService.updateScannerSuppliedStatuses(id);
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
					if (finding.getSurfaceLocation() != null) {
						finding.getSurfaceLocation().setPath(newPath);
					}
				}
			}
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void updateVulnerabilities(Application application, boolean shouldSaveVulnerabilites) {
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
							if (shouldSaveVulnerabilites) {
								vulnerabilityStatusService.closeVulnerability(vulnerabilities.get(j), null, null, false, false);
								vulnerabilityService.storeVulnerability(vulnerabilities.get(j));
							} else {
								vulnerabilities.get(j).setActive(false);
							}
						}
					}
				}
			}
		}
	}

	@Override
	public boolean processScan(Integer channelId, List<String> fileNames, List<String> originalFileNames,
							   Integer statusId, String userName) {

		if (channelId == null || fileNames == null || fileNames.isEmpty()) {
			log.error("processScan() received null input and was unable to finish.");
			return false;
		}

		Scan scan = processScanFiles(channelId, fileNames, originalFileNames, statusId);
		if (scan == null) {
			log.warn("processScanFile() failed to return a scan.");
			return false;
		}

		if (userName != null) {
			User user = userDao.retrieveByName(userName);
			scan.setUser(user);
		}

		scanDao.saveOrUpdate(scan);

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

		scanDao.saveOrUpdate(scan);

		scan.getApplicationChannel().getApplication().getScans().add(scan);

		// set auth parameters
		permissionsHandler.setPermissions(scan, scan.getApplicationChannel().getApplication().getId());

		// set numbers correctly
		vulnerabilityFilterService.updateVulnerabilities(
				scan.getApplicationChannel().getApplication().getOrganization().getId(),
				scan.getApplicationChannel().getApplication().getId(),
				null);

		return scan;
	}

	@Override
	public List<Scan> saveRemoteScansAndRun(List<Integer> channelIds, List<String> fileNames, List<String> originalNames) {

		List<Scan> scans = CollectionUtils.list();
		if (channelIds.size() != fileNames.size() || channelIds.size() != originalNames.size()) {
			return null;
		}

		for (int i = 0; i < channelIds.size() ; i++) {
			Scan scan = parseScan(channelIds.get(i), list(fileNames.get(i)), list(originalNames.get(i)), null);
			if (scan == null)
				return null;
			scans.add(scan);
		}
		Collections.sort(scans, Scan.getTimeComparator());

		if (channelIds.size() != scans.size())
			return null;

		for (int i=0; i<channelIds.size(); i++) {
			Scan scan = mergeScan(channelIds.get(i), scans.get(i), null);
			if (scan == null)
				return null;
		}

		for (Integer channelId: channelIds) {
			updateReportInfo(channelId);
		}

		return scans;
	}

	private Scan processScanFiles(Integer channelId, List<String> fileNames, List<String> originalFileNames, Integer statusId) {

		Scan combinedScan = mergeScan(channelId, parseScan(channelId, fileNames, originalFileNames, statusId), statusId);
		updateReportInfo(channelId);

		return combinedScan;
	}

	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}

	private Scan parseScan(Integer channelId, List<String> fileNames, List<String> originalFileNames, Integer statusId) {
		if (channelId == null || fileNames == null || fileNames.isEmpty()) {
			log.error("processScanFile() received null input and was unable to finish.");
			return null;
		}

		Scan combinedScan = new Scan();
		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);

		Calendar importTime = null;

		for(int i = 0; i < fileNames.size(); i++){
			String fileName = fileNames.get(i);

			File file = DiskUtils.getScratchFile(fileName);

			if (applicationChannel == null
					|| applicationChannel.getChannelType() == null
					|| !file.exists()) {
				log.warn("Invalid Application Channel, unable to find a ChannelImporter implementation.");
				return null;
			}

			// pick the appropriate parser
			ChannelImporter importer = channelImporterFactory.getChannelImporter(applicationChannel);

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
			scan.setOriginalFileNames(originalFileNames);
			scan.setSavedFileNames(getFileNames(fileNames));

			if(i == 0){
				combinedScan = scan;
				importTime = scan.getImportTime();
			} else {
				combinedScan.getFindings().addAll(scan.getFindings());
				combinedScan.getScanRepeatFindingMaps().addAll(scan.getScanRepeatFindingMaps());
				if(scan.getImportTime() != null && scan.getImportTime().after(importTime)){
					importTime = scan.getImportTime();
				}
			}

			importer.deleteScanFile();
		}

		combinedScan.setImportTime(importTime);

		return combinedScan;
	}

	private Scan mergeScan(Integer channelId, Scan combinedScan, Integer statusId) {

		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);

		if (combinedScan == null || applicationChannel == null)
			return null;

		updateJobStatus(statusId, "Findings successfully parsed, starting channel merge.");

		scanMerger.merge(combinedScan, applicationChannel);

		scanDao.saveOrUpdate(combinedScan);

		applicationChannel.getApplication().getScans().add(combinedScan);
		applicationChannel.getScanList().add(combinedScan);

		Set<Finding> findings = set();
		findings.addAll(combinedScan.getFindings());
		List<ScanRepeatFindingMap> scanRepeatFindingMaps = combinedScan.getScanRepeatFindingMaps();
		if (scanRepeatFindingMaps != null) {
			for (ScanRepeatFindingMap scanRepeatFindingMap : scanRepeatFindingMaps) {
				findings.add(scanRepeatFindingMap.getFinding());
			}
		}
		for (Finding finding : findings) {
			Vulnerability vulnerability = finding.getVulnerability();
			if (vulnerability != null) {
				vulnerabilityService.determineVulnerabilityDefectConsistencyState(vulnerability);
			}
		}

		return combinedScan;
	}

	private void updateReportInfo(Integer channelId){

		ApplicationChannel applicationChannel = applicationChannelDao.retrieveById(channelId);

		if (applicationChannel == null)
			return;

		vulnerabilityFilterService.updateVulnerabilities(
				applicationChannel.getApplication().getOrganization().getId(),
				applicationChannel.getApplication().getId(),
				null);

		vulnerabilityService.updateVulnerabilityReport(applicationChannel.getApplication());

	}

	private List<String> getFileNames(List<String> fullPathNames) {
		List<String> names = null;
			DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();
			if (defaultConfiguration.fileUploadLocationExists()) {
				names = list();
				for (String fullPathName : fullPathNames) {
					if (fullPathName != null) {
						Matcher m = scanFileRegex.matcher(fullPathName);
						if (m.matches()) {
							names.add(m.group(2));
						}
					}
				}
			}
		return names;
	}

}
