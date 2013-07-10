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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.channel.ChannelImporter;
import com.denimgroup.threadfix.service.channel.ChannelImporterFactory;

// TODO figure out this Transactional stuff
// TODO reorganize methods - not in a very good order right now.
@Service
@Transactional(readOnly = false)
public class ScanMergeServiceImpl implements ScanMergeService {

	private final SanitizedLogger log = new SanitizedLogger("ScanMergeService");
	
	private ChannelMerger channelMerger = null;
	private ApplicationScanMerger applicationScanMerger = null;
	private ScanDao scanDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelSeverityDao channelSeverityDao = null;
	private ApplicationChannelDao applicationChannelDao = null;
	private VulnerabilityDao vulnerabilityDao = null;
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	private ApplicationDao applicationDao = null;
	private UserDao userDao = null;
	private JobStatusService jobStatusService;

	private static final Set<String> VULNS_WITH_PARAMETERS_SET = 
			Collections.unmodifiableSet(new HashSet<>(Arrays.asList(GenericVulnerability.VULNS_WITH_PARAMS)));

	@Autowired
	public ScanMergeServiceImpl(ScanDao scanDao, ChannelTypeDao channelTypeDao,
			VulnerabilityDao vulnerabilityDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao,
			GenericVulnerabilityDao genericVulnerabilityDao,
			ApplicationChannelDao applicationChannelDao,
			ApplicationDao applicationDao,
			UserDao userDao,
			JobStatusService jobStatusService) {
		this.scanDao = scanDao;
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.genericVulnerabilityDao = genericVulnerabilityDao;
		this.applicationChannelDao = applicationChannelDao;
		this.applicationDao = applicationDao;
		this.userDao = userDao;
		this.jobStatusService = jobStatusService;
		this.channelMerger = new ChannelMerger(vulnerabilityDao);
		this.applicationScanMerger = new ApplicationScanMerger(applicationDao, scanDao, jobStatusService);
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

		return scan;
	}

	/**
	 * This method ensures that Findings have the correct relationship to the
	 * other objects before being committed to the database.
	 * 
	 * @param scan
	 */
	private void ensureValidLinks(Scan scan) {
		if (scan == null) {
			log.error("The scan processing was unable to complete because the supplied scan was null.");
			return;
		}

		if (scan.getImportTime() == null)
			scan.setImportTime(Calendar.getInstance());

		if (scan.getFindings() == null) {
			log.warn("There were no findings to process.");
			return;
		}

		int numWithoutPath = 0, numWithoutParam = 0;

		// we need to set up appropriate relationships between the scan's many
		// objects.
		SurfaceLocation surfaceLocation = null;
		for (Finding finding : scan.getFindings()) {
			if (finding == null) {
				continue;
			}

			finding.setScan(scan);

			surfaceLocation = finding.getSurfaceLocation();

			if (surfaceLocation != null) {
				surfaceLocation.setFinding(finding);
				if (surfaceLocation.getParameter() == null
						&& finding.getChannelVulnerability() != null
						&& finding.getChannelVulnerability()
								.getGenericVulnerability() != null
						&& VULNS_WITH_PARAMETERS_SET.contains(finding
								.getChannelVulnerability()
								.getGenericVulnerability().getName())) {
					numWithoutParam++;
				}
				if (surfaceLocation.getPath() == null
						|| surfaceLocation.getPath().trim().equals("")) {
					numWithoutPath++;
				}
			}

			if (finding.getDataFlowElements() != null) {
				for (DataFlowElement dataFlowElement : finding
						.getDataFlowElements()) {
					if (dataFlowElement != null) {
						dataFlowElement.setFinding(finding);
					}
				}
			}

			if (finding.getVulnerability() != null) {
				if (finding.getVulnerability().getFindings() == null) {
					finding.getVulnerability().setFindings(
							new ArrayList<Finding>());
					finding.getVulnerability().getFindings().add(finding);
				}
				finding.getVulnerability().setApplication(
						finding.getScan().getApplication());
				if (finding.getVulnerability().getId() == null) {
					vulnerabilityDao.saveOrUpdate(finding.getVulnerability());
				}

				if ((finding.getVulnerability().getOpenTime() == null)
						|| (finding.getVulnerability().getOpenTime()
								.compareTo(scan.getImportTime()) > 0))
					finding.getVulnerability()
							.setOpenTime(scan.getImportTime());
			}
		}

		if (numWithoutParam > 0) {
			log.warn("There are " + numWithoutParam
					+ " injection-based findings missing parameters. "
					+ "This could indicate a bug in the ThreadFix parser.");
		}

		if (numWithoutPath > 0) {
			log.warn("There are "
					+ numWithoutPath
					+ " findings missing paths. "
					+ "This probably means there is a bug in the ThreadFix parser.");
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void updateSurfaceLocation(Application application) {
		if (application != null && application.getProjectRoot() != null
				&& application.getVulnerabilities() != null) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || vuln.getFindings() == null)
					continue;
				for (Finding finding : vuln.getFindings()) {
					if (finding == null)
						continue;
					String newPath = getFindingPathWithRoot(finding,
							application.getProjectRoot());
					if (newPath == null)
						continue;
					if (finding.getSurfaceLocation() != null)
						finding.getSurfaceLocation().setPath(newPath);
				}
			}
		}
	}

	private void updateSurfaceLocation(Scan scan, String newRoot) {
		if (scan == null || scan.getFindings() == null || newRoot == null
				|| newRoot.trim().equals(""))
			return;

		for (Finding finding : scan.getFindings()) {
			String newPath = getFindingPathWithRoot(finding, newRoot);
			if (newPath == null)
				continue;
			if (finding.getSurfaceLocation() != null)
				finding.getSurfaceLocation().setPath(newPath);
		}
	}

	// TODO figure out what to do for dynamic scans when we update, right now we
	// discard the original path information
	private String getFindingPathWithRoot(Finding finding,
			String applicationRoot) {
		if (finding == null || applicationRoot == null)
			return null;

		String sourceFileName = null;

		if (!finding.getIsStatic() && finding.getSurfaceLocation() != null
				&& finding.getSurfaceLocation() != null)
			sourceFileName = finding.getSurfaceLocation().getPath();
		else if (finding.getIsStatic())
			sourceFileName = getStaticFindingPathGuess(finding);

		if (sourceFileName == null)
			return null;

		if (sourceFileName.contains("\\"))
			sourceFileName = sourceFileName.replace("\\", "/");

		if (sourceFileName.toLowerCase().contains(
				"/" + applicationRoot.toLowerCase())) {

			int index = sourceFileName.toLowerCase().indexOf(
					"/" + applicationRoot.toLowerCase());

			return sourceFileName.substring(index);
		}

		return null;
	}

	// this method finds the whole path up to and including any of the
	// extensions in suffixVals, the prefix will be taken out later
	private String getStaticFindingPathGuess(Finding finding) {
		String path = null;
		String[] suffixVals = { "aspx", "asp", "jsp", "php", "html", "htm",
				"java", "cs", "config", "js", "cgi", "ascx" };

		if (finding != null
				&& finding.getIsStatic()
				&& finding.getDataFlowElements() != null
				&& finding.getDataFlowElements().size() != 0
				&& finding.getDataFlowElements().get(0) != null
				&& finding.getDataFlowElements().get(0).getSourceFileName() != null) {
			path = finding.getDataFlowElements().get(0).getSourceFileName();

			for (String val : suffixVals) {
				if (!path.contains(val))
					continue;

				String temp = getRegexResult(path, "(.+\\." + val + ")");
				if (temp != null) {
					path = temp;
					break;
				}
			}
		}
		return path;
	}

	@Override
	@Transactional(readOnly = false)
	public void updateVulnerabilities(Application application) {
		List<Vulnerability> vulnerabilities = application.getVulnerabilities();
		
		FindingMatcher matcher = FindingMatcher.getBasicMatcher(application);

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

	private String getRegexResult(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null
				|| regex.isEmpty())
			return null;

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
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
	
		mergeScan(scan, scan.getApplicationChannel());
	
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
		ChannelImporterFactory factory = new ChannelImporterFactory(
				channelTypeDao, channelVulnerabilityDao, channelSeverityDao,
				genericVulnerabilityDao);
		ChannelImporter importer = factory
				.getChannelImporter(applicationChannel);
	
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
		
		mergeScan(scan, applicationChannel);
		
		importer.deleteScanFile();
		return scan;
	}

	private void mergeScan(Scan scan, ApplicationChannel applicationChannel) {
		if (scan.getFindings() != null && applicationChannel != null
				&& applicationChannel.getChannelType() != null
				&& applicationChannel.getChannelType().getName() != null) {
			log.info("The " + applicationChannel.getChannelType().getName()
					+ " import was successful" + " and found "
					+ scan.getFindings().size() + " findings.");
		}
	
		if (applicationChannel == null
				|| applicationChannel.getApplication() == null
				|| applicationChannel.getApplication().getId() == null) {
			log.error("An incorrectly configured application made it to processRemoteScan()");
			return;
		}
	
		updateProjectRoot(applicationChannel, scan);
		channelMerger.channelMerge(scan, applicationChannel);
		applicationScanMerger.applicationMerge(scan, applicationChannel.getApplication(), null);
	
		scan.setApplicationChannel(applicationChannel);
		scan.setApplication(applicationChannel.getApplication());
	
		if (scan.getNumberTotalVulnerabilities() != null
				&& scan.getNumberNewVulnerabilities() != null) {
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed processing with "
					+ scan.getNumberTotalVulnerabilities()
					+ " total Vulnerabilities ("
					+ scan.getNumberNewVulnerabilities() + " new).");
		} else {
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed.");
		}
	
		cleanFindings(scan);
		ensureValidLinks(scan);
		scanDao.saveOrUpdate(scan);
	}

	private void updateProjectRoot(ApplicationChannel applicationChannel, Scan scan) {
		String projectRoot = ProjectRootParser.findOrParseProjectRoot(applicationChannel, scan);
		if (projectRoot != null && applicationChannel.getApplication() != null
				&& applicationChannel.getApplication().getProjectRoot() == null) {
			applicationChannel.getApplication().setProjectRoot(projectRoot);
			updateSurfaceLocation(applicationChannel.getApplication());
			updateSurfaceLocation(scan, projectRoot);
		}
	}

	/**
	 * This method makes sure that the scan's findings don't have any database-incompatible field lengths
	 * 
	 * @param scan
	 */
	private void cleanFindings(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().size() == 0)
			return;

		for (Finding finding : scan.getFindings()) {
			if (finding == null)
				continue;

			if (finding.getLongDescription() != null
					&& finding.getLongDescription().length() > Finding.LONG_DESCRIPTION_LENGTH)
				finding.setLongDescription(finding.getLongDescription()
						.substring(0, Finding.LONG_DESCRIPTION_LENGTH - 1));
			if (finding.getNativeId() != null
					&& finding.getNativeId().length() > Finding.NATIVE_ID_LENGTH)
				finding.setNativeId(finding.getNativeId().substring(0,
						Finding.NATIVE_ID_LENGTH - 1));
			if (finding.getSourceFileLocation() != null
					&& finding.getSourceFileLocation().length() > Finding.SOURCE_FILE_LOCATION_LENGTH)
				finding.setSourceFileLocation(finding.getSourceFileLocation()
						.substring(0, Finding.SOURCE_FILE_LOCATION_LENGTH - 1));

			if (finding.getSurfaceLocation() != null) {
				SurfaceLocation location = finding.getSurfaceLocation();

				if (location.getHost() != null
						&& location.getHost().length() > SurfaceLocation.HOST_LENGTH)
					location.setHost(location.getHost().substring(0,
							SurfaceLocation.HOST_LENGTH - 1));
				if (location.getParameter() != null
						&& location.getParameter().length() > SurfaceLocation.PARAMETER_LENGTH)
					location.setParameter(location.getParameter().substring(0,
							SurfaceLocation.PARAMETER_LENGTH - 1));
				if (location.getPath() != null
						&& location.getPath().length() > SurfaceLocation.PATH_LENGTH)
					location.setPath(location.getPath().substring(0,
							SurfaceLocation.PATH_LENGTH - 1));
				if (location.getQuery() != null
						&& location.getQuery().length() > SurfaceLocation.QUERY_LENGTH)
					location.setQuery(location.getQuery().substring(0,
							SurfaceLocation.QUERY_LENGTH - 1));

				finding.setSurfaceLocation(location);
			}

			if (finding.getDataFlowElements() != null
					&& finding.getDataFlowElements().size() != 0) {
				for (DataFlowElement dataFlowElement : finding
						.getDataFlowElements()) {
					if (dataFlowElement.getLineText() != null
							&& dataFlowElement.getLineText().length() > DataFlowElement.LINE_TEXT_LENGTH)
						dataFlowElement.setLineText(dataFlowElement
								.getLineText().substring(0,
										DataFlowElement.LINE_TEXT_LENGTH - 1));
					if (dataFlowElement.getSourceFileName() != null
							&& dataFlowElement.getSourceFileName().length() > DataFlowElement.SOURCE_FILE_NAME_LENGTH)
						dataFlowElement
								.setSourceFileName(dataFlowElement
										.getSourceFileName()
										.substring(
												0,
												DataFlowElement.SOURCE_FILE_NAME_LENGTH - 1));
				}
			}
		}
	}

	/**
	 * Handle the Manual Finding edit submission. 
	 * It's a wrapper around the normal process manual finding method.
	 */
	@Override
	@Transactional(readOnly = false)
	public boolean processManualFindingEdit(Finding finding, Integer applicationId) {
		boolean result = processManualFinding(finding, applicationId);
		if (result && finding != null && finding.getScan() != null && 
				finding.getScan().getFindings() != null) {
			
			finding.getScan().setNumberTotalVulnerabilities(
					finding.getScan().getNumberTotalVulnerabilities() - 1);
			
			Finding oldFinding = null;

			int id = finding.getId();
			for (Finding scanFinding : finding.getScan().getFindings()) {
				if (scanFinding != finding && scanFinding.getId().equals(id)) {
					oldFinding = scanFinding;
				}
			}
			
			if (oldFinding != null) {
				finding.getScan().getFindings().remove(oldFinding);
				if (oldFinding.getVulnerability() != null && 
						oldFinding.getVulnerability().getFindings() != null) {
					Vulnerability vuln = oldFinding.getVulnerability();
					vuln.getFindings().remove(oldFinding);
					if (vuln.getFindings().size() == 0) {
						vuln.getApplication().getVulnerabilities().remove(vuln);
						vuln.setApplication(null);
						vulnerabilityDao.delete(vuln);
					}
				}
				vulnerabilityDao.evict(oldFinding);
			}
		}
		return result;
	}
	
	@Override
	@Transactional(readOnly = false)
	public boolean processManualFinding(Finding finding, Integer applicationId) {
		if (finding == null || applicationId == null) {
			log.debug("Null input to processManualFinding");
			return false;
		}
		
		ChannelType manualChannelType = channelTypeDao.retrieveByName(ChannelType.MANUAL);

		Scan scan = getManualScan(applicationId);
		if (scan == null || scan.getApplicationChannel() == null
				|| scan.getApplication() == null || scan.getFindings() == null) {
			log.debug("processManualFinding could not find or create the necessary manual scan.");
			return false;
		}

		String userName = SecurityContextHolder.getContext()
				.getAuthentication().getName();
		
		User user = userDao.retrieveByName(userName);
		finding.setUser(user);

		// Set the channelVulnerability
		ChannelVulnerability channelVulnerability = channelVulnerabilityDao
				.retrieveByCode(manualChannelType,
						finding.getChannelVulnerability().getCode());
		finding.setChannelVulnerability(channelVulnerability);

		if (finding.getChannelSeverity() != null &&
				finding.getChannelSeverity().getId() != null) {
			// Set the channelSeverity so we can get the corresponding
			// genericSeverity when appMerge is called.
			ChannelSeverity channelSeverity = channelSeverityDao
					.retrieveById(finding.getChannelSeverity().getId());
			finding.setChannelSeverity(channelSeverity);
		} else {
			ChannelSeverity channelSeverity = channelSeverityDao
					.retrieveByCode(manualChannelType, GenericSeverity.MEDIUM);
			finding.setChannelSeverity(channelSeverity);
		}

		if (!finding.getIsStatic()) {
			finding.setDataFlowElements(null);
		} else {
			String path = getStaticFindingPathGuess(finding);
			if (path != null
					&& scan.getApplication().getProjectRoot() != null
					&& scan.getApplication().getProjectRoot().toLowerCase() != null
					&& path.toLowerCase().contains(
							scan.getApplication().getProjectRoot()
									.toLowerCase())) {
				path = path.substring(path.toLowerCase().indexOf(
						scan.getApplication().getProjectRoot().toLowerCase()));
			}
			finding.getSurfaceLocation().setPath(path);
		}

		Scan tempScan = new Scan();
		tempScan.setFindings(new ArrayList<Finding>());
		tempScan.getFindings().add(finding);
		applicationScanMerger.applicationMerge(tempScan, applicationId, null);

		scan.getFindings().add(finding);
		scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities() + 1);
		finding.setScan(scan);
		ensureValidLinks(scan);
		scanDao.saveOrUpdate(scan);
		log.debug("Manual Finding submission was successful.");
		log.debug(userName + " has added a new finding to the Application " + 
				finding.getScan().getApplication().getName());
		return true;
	}

	private Scan getManualScan(Integer applicationId) {
		if (applicationId == null)
			return null;

		ApplicationChannel applicationChannel = null;
		ChannelType manualChannel = channelTypeDao
				.retrieveByName(ChannelType.MANUAL);
		if (manualChannel != null)
			applicationChannel = applicationChannelDao
					.retrieveByAppIdAndChannelId(applicationId,
							manualChannel.getId());

		if (applicationChannel != null
				&& applicationChannel.getScanList() != null
				&& applicationChannel.getScanList().size() != 0) {
			return applicationChannel.getScanList().get(0);
		}

		Scan newManualScan = initializeNewManualScan(applicationId);

		if (applicationChannel == null)
			applicationChannel = createManualApplicationChannel(applicationId);

		if (applicationChannel == null)
			return null;

		newManualScan.setApplicationChannel(applicationChannel);

		return newManualScan;
	}

	private Scan initializeNewManualScan(Integer applicationId) {
		if (applicationId == null)
			return null;

		Application application = applicationDao.retrieveById(applicationId);
		if (application == null)
			return null;

		Scan scan = new Scan();
		scan.setApplication(application);

		List<Finding> findingList = new ArrayList<Finding>();
		scan.setFindings(findingList);

		scan.setNumberNewVulnerabilities(0);
		scan.setNumberOldVulnerabilities(0);
		scan.setNumberClosedVulnerabilities(0);
		scan.setNumberTotalVulnerabilities(0);
		scan.setNumberResurfacedVulnerabilities(0);
		scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(0);

		return scan;
	}

	private ApplicationChannel createManualApplicationChannel(
			Integer applicationId) {
		if (applicationId == null)
			return null;

		Application application = applicationDao.retrieveById(applicationId);
		if (application == null) {
			return null;
		}

		ApplicationChannel applicationChannel = new ApplicationChannel();
		applicationChannel.setApplication(application);
		ChannelType manualChannel = channelTypeDao
				.retrieveByName(ChannelType.MANUAL);
		applicationChannel.setChannelType(manualChannel);

		if (application.getChannelList() == null)
			application.setChannelList(new ArrayList<ApplicationChannel>());

		application.getChannelList().add(applicationChannel);
		applicationChannelDao.saveOrUpdate(applicationChannel);
		applicationDao.saveOrUpdate(application);
		return applicationChannel;
	}

	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}
	
	private void updateScanCounts(Scan scan) {
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
