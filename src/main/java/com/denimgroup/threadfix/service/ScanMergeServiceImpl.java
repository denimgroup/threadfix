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

import java.io.File;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
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
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
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

	// These generic types should have parameters
	private static final String[] VULNS_WITH_PARAMS = { 
			GenericVulnerability.CWE_CROSS_SITE_SCRIPTING,
			GenericVulnerability.CWE_BLIND_XPATH_INJECTION,
			GenericVulnerability.CWE_EVAL_INJECTION,
			GenericVulnerability.CWE_FORMAT_STRING_INJECTION,
			GenericVulnerability.CWE_LDAP_INJECTION,
			GenericVulnerability.CWE_XPATH_INJECTION,
			GenericVulnerability.CWE_SQL_INJECTION,
			GenericVulnerability.CWE_OS_COMMAND_INJECTION,
			GenericVulnerability.CWE_GENERIC_INJECTION
		};
	
	private static final Set<String> VULNS_WITH_PARAMETERS_SET = new TreeSet<String>();
	
	static {
		Collections.addAll(VULNS_WITH_PARAMETERS_SET, VULNS_WITH_PARAMS);
	}

	// This string makes getting the applicationRoot simpler.
	private String projectRoot = null;

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

		processFindings(scan);
		scanDao.saveOrUpdate(scan);

		return scan;
	}

	/**
	 * This method ensures that Findings have the correct relationship to the
	 * other objects before being committed to the database.
	 * 
	 * @param scan
	 */
	private void processFindings(Scan scan) {
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

		if (vulnerabilities != null) {
			for (int i = 0; i < vulnerabilities.size(); i++) {
				if (vulnerabilities.get(i).getFindings() != null
						&& vulnerabilities.get(i).getFindings().size() > 0) {
					Finding finding = vulnerabilities.get(i).getFindings()
							.get(0);
					for (int j = i + 1; j < vulnerabilities.size(); j++) {
						if (doesMatch(finding, vulnerabilities.get(j))) {

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
//	@Transactional
	public boolean processScan(Integer channelId, String fileName) {
		return processScan(channelId, fileName, null, null);
	}

	@Override
//	@Transactional
	public boolean processScan(Integer channelId, String fileName,
			Integer statusId, String userName) {
				
		if (channelId == null || fileName == null) {
			log.error("processScan() received null input and was unable to finish.");
			return false;
		}

		Scan scan = processScanFile(channelId, fileName, statusId);
		if (scan == null) {
			log.warn("processScanFile() failed to return a scan.");
			return false;//"vulnerability"
		}

		processFindings(scan);
		
		scanDao.saveOrUpdate(scan);
		
		if (userName != null) {
			User user = userDao.retrieveByName(userName);
			scan.setUser(user);
		}
		
		scanDao.saveOrUpdate(scan);
		
		return true;
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

		updateJobStatus(statusId, "Parsing findings from " + applicationChannel.getChannelType().getName() + " scan file.");
		log.info("Processing file " + fileName + " on channel "
				+ applicationChannel.getChannelType().getName() + ".");

		importer.setFileName(fileName);
		Scan scan = importer.parseInput();

		if (scan == null) {
			log.warn("The " + applicationChannel.getChannelType().getName()
					+ " import failed for file " + fileName + ".");
			return null;
		}

		if (scan.getFindings() != null) {
			log.info("The " + applicationChannel.getChannelType().getName()
					+ " import was successful for file " + fileName
					+ " and found " + scan.getFindings().size() + " findings.");
		}
		
		updateJobStatus(statusId, "Findings successfully parsed, starting channel merge.");

		projectRoot = null;
		findOrParseProjectRoot(applicationChannel, scan);
		channelMerge(scan, applicationChannel);
		appMerge(scan, applicationChannel.getApplication().getId(), statusId);

		scan.setApplicationChannel(applicationChannel);
		scan.setApplication(applicationChannel.getApplication());

		if (scan.getNumberTotalVulnerabilities() != null
				&& scan.getNumberNewVulnerabilities() != null)
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed processing with "
					+ scan.getNumberTotalVulnerabilities()
					+ " total Vulnerabilities ("
					+ scan.getNumberNewVulnerabilities() + " new).");
		else
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed.");

		cleanFindings(scan);
		importer.deleteScanFile();
		return scan;
	}

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

	@Override
	@Transactional(readOnly = false)
	public boolean processManualFinding(Finding finding, Integer applicationId,
			String userName) {
		if (finding == null || applicationId == null) {
			log.debug("Null input to processManualFinding");
			return false;
		}

		Scan scan = getManualScan(applicationId);
		if (scan == null || scan.getApplicationChannel() == null
				|| scan.getApplication() == null || scan.getFindings() == null) {
			log.debug("processManualFinding could not find or create the necessary manual scan.");
			return false;
		}

		User user = userDao.retrieveByName(userName);
		finding.setUser(user);

		// Set the channelVulnerability
		ChannelVulnerability channelVulnerability = channelVulnerabilityDao
				.retrieveByCode(
						channelTypeDao.retrieveByName(ChannelType.MANUAL),
						finding.getChannelVulnerability().getCode());
		finding.setChannelVulnerability(channelVulnerability);

		// Set the channelSeverity so we can get the corresponding
		// genericSeverity when appMerge is called.
		ChannelSeverity channelSeverity = channelSeverityDao
				.retrieveById(finding.getChannelSeverity().getId());
		finding.setChannelSeverity(channelSeverity);

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
		appMerge(tempScan, applicationId, null);

		scan.getFindings().add(finding);
		scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities() + 1);
		finding.setScan(scan);
		processFindings(scan);
		scanDao.saveOrUpdate(scan);
		log.debug("Manual Finding submission was successful.");
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

	// TODO test this parser on other projects than RiskE
	private void findOrParseProjectRoot(ApplicationChannel applicationChannel,
			Scan scan) {
		if (applicationChannel.getApplication() != null
				&& applicationChannel.getApplication().getProjectRoot() != null
				&& !applicationChannel.getApplication().getProjectRoot().trim()
						.equals("")) {
			projectRoot = applicationChannel.getApplication().getProjectRoot()
					.toLowerCase();
		}

		// These next two if statements handle the automatic project root
		// parsing.
		if (projectRoot == null)
			projectRoot = parseProjectRoot(scan);

		if (projectRoot != null && applicationChannel.getApplication() != null
				&& applicationChannel.getApplication().getProjectRoot() == null) {
			applicationChannel.getApplication().setProjectRoot(projectRoot);
			updateSurfaceLocation(applicationChannel.getApplication());
			updateSurfaceLocation(scan, projectRoot);
		}
	}

	private String parseProjectRoot(Scan scan) {
		if (scan == null || scan.getFindings() == null
				|| scan.getFindings().size() == 0)
			return null;

		String commonPrefix = null;

		for (Finding finding : scan.getFindings()) {
			if (finding.getIsStatic()) {
				List<DataFlowElement> dataFlowElements = finding
						.getDataFlowElements();
				if (dataFlowElements == null || dataFlowElements.size() == 0)
					continue;

				Collections.sort(dataFlowElements);

				if (dataFlowElements.get(0) != null
						&& dataFlowElements.get(0).getSourceFileName() != null) {
					if (commonPrefix == null)
						commonPrefix = dataFlowElements.get(0)
								.getSourceFileName();
					else
						commonPrefix = findCommonPrefix(dataFlowElements.get(0)
								.getSourceFileName(), commonPrefix);
				}
			}
		}

		if (commonPrefix != null && !commonPrefix.equals("")) {
			if (commonPrefix.contains("/")) {
				while (commonPrefix.endsWith("/"))
					commonPrefix = commonPrefix.substring(0,
							commonPrefix.length() - 1);
				if (commonPrefix.contains("/"))
					commonPrefix = commonPrefix.substring(
							commonPrefix.lastIndexOf("/") + 1).replace("/", "");
			}
		}

		return commonPrefix;
	}

	private String findCommonPrefix(String newString, String oldString) {
		if (newString == null || oldString == null)
			return "";
		if (newString.toLowerCase().contains(oldString.toLowerCase()))
			return oldString;

		String newLower = newString.replace("\\", "/").toLowerCase();
		String oldLower = oldString.replace("\\", "/").toLowerCase();

		String returnString = "";

		for (String string : oldLower.split("/")) {
			String tempString = returnString.concat(string + "/");
			if (newLower.startsWith(tempString))
				returnString = tempString;
			else
				break;
		}

		return oldString.replace("\\", "/").substring(0, returnString.length());
	}

	/**
	 * This method weeds out all of the repeat Findings to provide a cleaner
	 * merge later in appMerge().
	 * 
	 * @param scan
	 * @param applicationChannel
	 */
	private void channelMerge(Scan scan, ApplicationChannel applicationChannel) {
		if (scan == null || applicationChannel == null) {
			log.warn("Insufficient data to complete Application Channel-wide merging process.");
			return;
		}

		if (scan.getFindings() == null)
			scan.setFindings(new ArrayList<Finding>());

		List<Finding> oldFindings = new ArrayList<Finding>();
		List<Finding> newFindings = new ArrayList<Finding>();
		Map<String, Finding> scanHash = new HashMap<String, Finding>();
		Map<String, Vulnerability> oldNativeIdVulnHash = new HashMap<String, Vulnerability>();
		Map<String, Finding> oldNativeIdFindingHash = new HashMap<String, Finding>();
		Set<Integer> alreadySeenVulnIds = new TreeSet<Integer>();
		Integer closed = 0, resurfaced = 0, total = 0, numberNew = 0, old = 0, numberRepeatResults = 0, numberRepeatFindings = 0, oldVulnerabilitiesInitiallyFromThisChannel = 0;

		log.info("Starting Application Channel-wide merging process with "
				+ scan.getFindings().size() + " findings.");
		for (Finding finding : scan.getFindings()) {
			if (finding != null && finding.getNativeId() != null
					&& !finding.getNativeId().isEmpty()) {
				if (scanHash.containsKey(finding.getNativeId())) {
					// Increment the merged results counter in the finding
					// object in the hash
					scanHash.get(finding.getNativeId()).setNumberMergedResults(
							scanHash.get(finding.getNativeId())
									.getNumberMergedResults() + 1);
				} else {
					scanHash.put(finding.getNativeId(), finding);
				}
			}
		}

		log.info("After filtering out duplicate native IDs, there are "
				+ scanHash.keySet().size() + " findings.");

		if (applicationChannel != null
				&& applicationChannel.getScanList() != null)
			for (Scan oldScan : applicationChannel.getScanList())
				if (oldScan != null && oldScan.getId() != null
						&& oldScan.getFindings() != null
						&& oldScan.getFindings().size() != 0)
					oldFindings.addAll(oldScan.getFindings());

		for (Finding finding : oldFindings) {
			if (finding != null && finding.getNativeId() != null
					&& !finding.getNativeId().isEmpty()) {
				oldNativeIdVulnHash.put(finding.getNativeId(),
						finding.getVulnerability());
				oldNativeIdFindingHash.put(finding.getNativeId(), finding);
			}
		}

		for (String nativeId : scanHash.keySet()) {
			if (oldNativeIdVulnHash.containsKey(nativeId)) {
				Finding oldFinding = oldNativeIdFindingHash.get(nativeId), newFinding = scanHash
						.get(nativeId);

				// If the finding has been newly marked a false positive, update
				// the existing finding / vuln
				if (newFinding.isMarkedFalsePositive()
						&& !oldFinding.isMarkedFalsePositive()) {
					log.info("A previously imported finding has been marked a false positive "
							+ "in the scan results. Marking the finding and Vulnerability.");
					oldFinding.setMarkedFalsePositive(true);
					if (oldFinding.getVulnerability() != null) {
						oldFinding.getVulnerability().setIsFalsePositive(true);
						vulnerabilityDao.saveOrUpdate(oldFinding
								.getVulnerability());
					}
				}

				numberRepeatFindings += 1;
				numberRepeatResults += newFinding.getNumberMergedResults();
				// add it to the old finding maps so that we can know that it
				// was here later
				// the constructor maps everything correctly
				new ScanRepeatFindingMap(oldFinding, scan);
			}

			if (oldNativeIdVulnHash.containsKey(nativeId)
					&& oldNativeIdVulnHash.get(nativeId) != null
					&& !alreadySeenVulnIds.contains(oldNativeIdVulnHash.get(
							nativeId).getId())) {
				Vulnerability vulnerability = oldNativeIdVulnHash.get(nativeId);
				alreadySeenVulnIds.add(vulnerability.getId());

				if (applicationChannel.getId() != null
						&& vulnerability.getOriginalFinding() != null
						&& vulnerability.getOriginalFinding().getScan() != null
						&& vulnerability.getOriginalFinding().getScan()
								.getApplicationChannel() != null
						&& applicationChannel.getId().equals(
								vulnerability.getOriginalFinding().getScan()
										.getApplicationChannel().getId())) {
					oldVulnerabilitiesInitiallyFromThisChannel += 1;
				}

				old += 1;
				total += 1;

				if (!vulnerability.isActive()) {
					resurfaced += 1;
					vulnerability.reopenVulnerability(scan,
							scan.getImportTime());
					vulnerabilityDao.saveOrUpdate(vulnerability);
				}
			} else {
				if (!oldNativeIdVulnHash.containsKey(nativeId)) {
					numberNew += 1;
					total += 1;
					newFindings.add(scanHash.get(nativeId));
				}
			}
		}

		for (String nativeId : oldNativeIdVulnHash.keySet()) {
			if (!scanHash.containsKey(nativeId)
					&& oldNativeIdVulnHash.get(nativeId) != null
					&& oldNativeIdVulnHash.get(nativeId).isActive()) {
				if (scan.getImportTime() != null)
					oldNativeIdVulnHash.get(nativeId).closeVulnerability(scan,
							scan.getImportTime());
				else
					oldNativeIdVulnHash.get(nativeId).closeVulnerability(scan,
							Calendar.getInstance());
				vulnerabilityDao
						.saveOrUpdate(oldNativeIdVulnHash.get(nativeId));
				closed += 1;
			}
		}

		log.info("Merged " + old + " Findings to old findings by native ID.");
		log.info("Closed " + closed + " old vulnerabilities.");
		log.info(numberRepeatResults
				+ " results were repeats from earlier scans and were not included in this scan.");
		log.info(resurfaced + " vulnerabilities resurfaced in this scan.");
		log.info("Scan completed channel merge with " + numberNew
				+ " new Findings.");

		scan.setNumberNewVulnerabilities(numberNew);
		scan.setNumberOldVulnerabilities(old);
		scan.setNumberTotalVulnerabilities(total);
		scan.setNumberClosedVulnerabilities(closed);
		scan.setNumberResurfacedVulnerabilities(resurfaced);
		scan.setNumberRepeatResults(numberRepeatResults);
		scan.setNumberRepeatFindings(numberRepeatFindings);
		scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(oldVulnerabilitiesInitiallyFromThisChannel);

		scan.setFindings(newFindings);
	}

	/**
	 * This method does the actual vulnerability merging across the app.
	 * 
	 * @param scan
	 * @param appId
	 */
	private void appMerge(Scan scan, int appId, Integer statusId) {
		
		updateJobStatus(statusId, "Channel merge completed. Starting application merge.");
		
		int initialOld = 0, numUnableToParseVuln = 0, numMergedInsideScan = 0;
		
		// We may want to take this back although I don't think it's really hurting anything here
		scanDao.saveOrUpdate(scan);
		
		Application application = applicationDao.retrieveById(appId);
		List<Vulnerability> vulns = null;
		if (application != null)
			vulns = application.getVulnerabilities();

		if (vulns == null || scan == null || scan.getFindings() == null) {
			log.warn("There was insufficient data to perform an application merge.");
			return;
		}

		List<Vulnerability> newVulns = new ArrayList<Vulnerability>();
		HashMap<Vulnerability, Integer> alreadySeenVulns = new HashMap<Vulnerability, Integer>();

		boolean hasStatistics = scan.getNumberNewVulnerabilities() != null
				&& scan.getNumberOldVulnerabilities() != null
				&& scan.getNumberTotalVulnerabilities() != null;

		if (hasStatistics) {
			initialOld = scan.getNumberOldVulnerabilities();
		}

		long interval = 0, count = 0, soFar = 0;
		boolean logging = false;

		interval = scan.getFindings().size() / 10;
		
		if (scan.getFindings().size() > 10000) {
			logging = true;
			log.info("The scan has more than 10,000 findings, ThreadFix will print a message every "
					+ interval + " (~10%) findings processed.");
		}

		log.info("Starting Application-wide merge process with "
				+ scan.getFindings().size() + " findings.");
		for (Finding finding : scan.getFindings()) {

			count++;
			if (count > interval) {
				soFar += count;
				count = 0;
				String statusString = "Processed " + soFar + " out of "
						+ scan.getFindings().size() + " findings.";
				
				updateJobStatus(statusId, statusString);
				
				if (logging) {
					log.info(statusString);
				}
			}

			boolean match = false;

			for (Vulnerability vuln : vulns) {
				match = doesMatch(finding, vuln);
				if (match) {
					finding.setFirstFindingForVuln(false);

					// Again, we don't want to count old vulns that we match
					// against more than once
					// so we keep track of those using a hash.
					if (alreadySeenVulns.get(vuln) == null) {
						alreadySeenVulns.put(vuln, 1);
						if (hasStatistics) {
							scan.setNumberNewVulnerabilities(scan
									.getNumberNewVulnerabilities() - 1);
							scan.setNumberOldVulnerabilities(scan
									.getNumberOldVulnerabilities() + 1);
							Finding previousFinding = vuln.getOriginalFinding();

							// Update records for the vuln origin
							if (previousFinding != null
									&& previousFinding.getScan() != null
									&& previousFinding.getScan() != null
									&& previousFinding.getScan()
											.getApplicationChannel() != null
									&& scan.getApplicationChannel()
											.getId()
											.equals(previousFinding.getScan()
													.getApplicationChannel()
													.getId())) {
								// must be older
								scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(scan
										.getNumberOldVulnerabilitiesInitiallyFromThisChannel() + 1);
							} else if (previousFinding != null
									&& previousFinding.getScan()
											.getImportTime()
											.after(scan.getImportTime())) {
								// replace as oldest finding for vuln
								// first, switch the flags. Then update new /
								// old counts on both scans.
								finding.setFirstFindingForVuln(true);
								scan.setNumberNewVulnerabilities(scan
										.getNumberNewVulnerabilities() + 1);
								scan.setNumberOldVulnerabilities(scan
										.getNumberOldVulnerabilities() - 1);

								correctExistingScans(previousFinding);
							}
						}
					} else if (hasStatistics) {
						scan.setNumberNewVulnerabilities(scan
								.getNumberNewVulnerabilities() - 1);
						scan.setNumberTotalVulnerabilities(scan
								.getNumberTotalVulnerabilities() - 1);
					}

					addToVuln(vuln, finding);
					break;
				}
			}

			// if the generated vulnerability didn't match any that were in the
			// db, compare it to valid new vulns still in memory
			if (!match) {
				for (Vulnerability newVuln : newVulns) {
					match = doesMatch(finding, newVuln);
					if (match) {
						finding.setFirstFindingForVuln(false);

						numMergedInsideScan += 1;
						if (hasStatistics) {
							scan.setNumberTotalVulnerabilities(scan
									.getNumberTotalVulnerabilities() - 1);
							scan.setNumberNewVulnerabilities(scan
									.getNumberNewVulnerabilities() - 1);
						}

						addToVuln(newVuln, finding);
						break;
					}
				}
			}

			// if it wasn't found there either, we need to save it.
			// it gets counted as new if a vuln is successfully parsed.
			if (!match) {
				Vulnerability newVuln = parseVulnerability(finding);
				if (newVuln == null) {
					numUnableToParseVuln += 1;
					if (hasStatistics) {
						scan.setNumberTotalVulnerabilities(scan
								.getNumberTotalVulnerabilities() - 1);
						scan.setNumberNewVulnerabilities(scan
								.getNumberNewVulnerabilities() - 1);
					}
					continue;
				}
				newVuln.setFindings(new ArrayList<Finding>());
				newVuln.getFindings().add(finding);
				newVulns.add(newVuln);
				finding.setFirstFindingForVuln(true);
				finding.setVulnerability(newVuln);
			}
		}
		if (hasStatistics) {
			log.info("Number of findings merged to other findings from this scan: "
					+ numMergedInsideScan);
			log.info("Number of findings that couldn't be parsed into vulnerabilities: "
					+ numUnableToParseVuln);
			log.info("Number of findings merged to old vulnerabilities in application merge: "
					+ (scan.getNumberOldVulnerabilities() - initialOld));
			log.info("Finished application merge. The scan now has "
					+ scan.getNumberNewVulnerabilities()
					+ " new vulnerabilities.");
		} else {
			log.info("Finished application merge.");
		}
	}

	private void addToVuln(Vulnerability vuln, Finding finding) {
		vuln.getFindings().add(finding);

		// update the generic severity
		if (vuln.getGenericSeverity() == null
				|| (vuln.getGenericSeverity().getName() != null
						&& finding.getChannelSeverity() != null
						&& getGenericSeverity(finding.getChannelSeverity()) != null
						&& getGenericSeverity(finding.getChannelSeverity())
								.getName() != null && GenericSeverity.NUMERIC_MAP
						.get(vuln.getGenericSeverity().getName()) < GenericSeverity.NUMERIC_MAP
						.get(getGenericSeverity(finding.getChannelSeverity())
								.getName()))) {
			vuln.setGenericSeverity(getGenericSeverity(finding
					.getChannelSeverity()));
		}

		finding.setVulnerability(vuln);
	}

	/**
	 * This method corrects newer scans that were uploaded first in a different
	 * channel. They need to have their counts updated slightly.
	 * 
	 * @param finding
	 */
	private void correctExistingScans(Finding finding) {
		finding.getVulnerability().setSurfaceLocation(
				finding.getVulnerability().getOriginalFinding()
						.getSurfaceLocation());
		finding.setFirstFindingForVuln(false);
		finding.getScan().setNumberNewVulnerabilities(
				finding.getScan().getNumberNewVulnerabilities() - 1);
		finding.getScan().setNumberOldVulnerabilities(
				finding.getScan().getNumberOldVulnerabilities() + 1);

		if (finding.getScanRepeatFindingMaps() != null) {
			for (ScanRepeatFindingMap map : finding.getScanRepeatFindingMaps()) {
				if (map.getScan() != null
						&& map.getScan()
								.getNumberOldVulnerabilitiesInitiallyFromThisChannel() != null) {
					map.getScan()
							.setNumberOldVulnerabilitiesInitiallyFromThisChannel(
									map.getScan()
											.getNumberOldVulnerabilitiesInitiallyFromThisChannel() - 1);
				}
			}
		}

		scanDao.saveOrUpdate(finding.getScan());
	}

	/**
	 * This is the method that determines whether a finding matches a
	 * vulnerability.
	 * 
	 * @param finding
	 * @param vuln
	 * @return
	 */
	private boolean doesMatch(Finding finding, Vulnerability vuln) {
		if (finding == null || vuln == null)
			return false;

		// iterate through the findings of the vulnerability and try to match
		// them to the finding
		for (Finding vulnFinding : vuln.getFindings()) {
			if (!finding.getIsStatic()) {
				if (!vulnFinding.getIsStatic()
						&& dynamicToDynamicMatch(finding, vulnFinding))
					return true;
				else if (vulnFinding.getIsStatic()
						&& dynamicToStaticMatch(finding, vulnFinding))
					return true;
			} else if (finding.getIsStatic()) {
				if (!vulnFinding.getIsStatic()
						&& dynamicToStaticMatch(vulnFinding, finding))
					return true;
				else if (vulnFinding.getIsStatic()
						&& staticToStaticMatch(finding, vulnFinding))
					return true;
			}
		}

		return false;
	}

	/**
	 * If a static finding is merged to a vulnerability with at least one static
	 * finding, this method is used to figure out whether they should be merged.
	 * 
	 * @param oldFinding
	 * @param newFinding
	 * @return
	 */
	private boolean staticToStaticMatch(Finding oldFinding, Finding newFinding) {
		if (oldFinding == null || newFinding == null)
			return false;

		// check that parameters match
		if (oldFinding.getSurfaceLocation() != null
				&& newFinding.getSurfaceLocation() != null
				&& (oldFinding.getSurfaceLocation().getParameter() == null
						|| newFinding.getSurfaceLocation().getParameter() == null || !oldFinding
						.getSurfaceLocation().getParameter()
						.equals(newFinding.getSurfaceLocation().getParameter())))
			return false;

		// check that generic vulns match
		if (getGenericVulnerability(oldFinding.getChannelVulnerability()) == null
				|| getGenericVulnerability(newFinding.getChannelVulnerability()) == null
				|| !getGenericVulnerability(
						oldFinding.getChannelVulnerability()).getId().equals(
						getGenericVulnerability(
								newFinding.getChannelVulnerability()).getId()))
			return false;

		// If match, compare their DataFlowElement (source file name, line
		// number and column number)
		List<DataFlowElement> oldDataFlowElements = oldFinding
				.getDataFlowElements();
		List<DataFlowElement> newDataFlowElements = newFinding
				.getDataFlowElements();

		// If they are not empty, sort them and continue
		if (oldDataFlowElements != null && oldDataFlowElements.size() != 0
				&& newDataFlowElements != null
				&& newDataFlowElements.size() != 0) {

			Collections.sort(oldDataFlowElements);
			Collections.sort(newDataFlowElements);

			// If both of the DataFlowElement Lists are of size 1, compare
			// them directly.
			if (oldDataFlowElements.size() == 1
					&& newDataFlowElements.size() == 1) {
				return compareDataFlowElements(oldDataFlowElements.get(0),
						newDataFlowElements.get(0));
			}
			// Otherwise, compare the source and the sink of the two
			// DateFlowElement.
			else {
				return compareDataFlowElements(oldDataFlowElements.get(0),
						newDataFlowElements.get(0))
						&& compareDataFlowElements(
								oldDataFlowElements.get(oldDataFlowElements
										.size() - 1),
								newDataFlowElements.get(newDataFlowElements
										.size() - 1));
			}
		}

		return false;
	}

	// TODO improve this method
	private boolean dynamicToStaticMatch(Finding dynamicFinding,
			Finding staticFinding) {
		if (dynamicFinding == null || staticFinding == null)
			return false;

		// check to make sure they have the same generic vulnerability - this
		// part should be ok across types of scanners
		GenericVulnerability dynamicFindingGenericVuln = getGenericVulnerability(dynamicFinding
				.getChannelVulnerability());
		GenericVulnerability staticFindingGenericVuln = getGenericVulnerability(staticFinding
				.getChannelVulnerability());

		if (dynamicFindingGenericVuln != null
				&& dynamicFindingGenericVuln.getId() != null
				&& staticFindingGenericVuln != null
				&& staticFindingGenericVuln.getId() != null
				&& dynamicFindingGenericVuln.getId().equals(
						staticFindingGenericVuln.getId())) {

			// TODO hash out exactly what to do here in all the cases

			// check to see that they have the same path
			if (dynamicFinding.getSurfaceLocation() != null
					&& staticFinding.getSurfaceLocation() != null) {

				// the static parameter and path have been guessed at by the
				// individual scanner
				// TODO look at how this guessing takes place / maybe move the
				// guessing here
				String dynamicParam = dynamicFinding.getSurfaceLocation()
						.getParameter();
				String staticParam = staticFinding.getSurfaceLocation()
						.getParameter();
				String dynamicPath = dynamicFinding.getSurfaceLocation()
						.getPath();
				String staticPath = staticFinding.getSurfaceLocation()
						.getPath();

				if (!dynamicPath.startsWith("/"))
					dynamicPath = "/".concat(dynamicPath);
				if (!staticPath.startsWith("/"))
					staticPath = "/".concat(staticPath);

				if (dynamicPath != null && !dynamicPath.trim().equals("")
						&& staticPath != null && !staticPath.trim().equals("")
						&& dynamicPath.equals(staticPath)) {

					// barring cases where faulty URL parsing returned a
					// matching URL,
					// the findings are on the same page at this point.
					if ((dynamicParam == null || dynamicParam.trim().equals(""))
							&& (staticParam == null || staticParam.trim()
									.equals("")))
						// if they don't have params, they can be offered as a
						// potential match
						return true;
					else if ((dynamicParam == null || dynamicParam.trim()
							.equals(""))
							|| (staticParam == null)
							|| staticParam.trim().equals(""))
						// if we get here, one or the other parameter is null,
						// and should be offered as a potential match
						return false;
					else if (dynamicParam.equals(staticFinding
							.getSurfaceLocation().getParameter()))
						// if they match all three things, they can be
						// automatically matched
						return true;
					else
						// if the code reaches this point the parameters are
						// different and the findings should not be merged
						return false;
				} else {

					// if we get here, the paths didn't match for one reason or
					// another.
					// if they have the same parameters, we should offer them as
					// a potential match,
					// because parsing a URL is not very reliable
					// check to see that the parameters match or are both
					// missing
					if ((dynamicParam == null || dynamicParam.trim().equals(""))
							&& ((staticParam == null) || staticParam.trim()
									.equals("")))
						// if they don't have params, they can't be matched (and
						// shouldn't be in the system)
						return false;
					else if ((dynamicParam == null || dynamicParam.trim()
							.equals(""))
							|| (staticParam == null)
							|| staticParam.trim().equals(""))
						// if we get here, one or the other parameter is null,
						// and could be offered as a potential match
						// because path parsing may have failed.
						return false;
					else if (dynamicParam.equals(staticFinding
							.getSurfaceLocation().getParameter()))
						// if they have the same param, they should be offered
						// as a potential match
						return false;
					else
						// null location and no parameter means no match.
						return false;
				}
			}
		}

		return false;
	}

	// both findings are assumed to be dynamic.
	private boolean dynamicToDynamicMatch(Finding newFinding, Finding oldFinding) {
		if (newFinding == null || oldFinding == null)
			return false;

		// check to make sure they have the same generic vulnerability
		GenericVulnerability newFindingGenericVuln = getGenericVulnerability(newFinding
				.getChannelVulnerability());
		GenericVulnerability oldFindingGenericVuln = getGenericVulnerability(oldFinding
				.getChannelVulnerability());

		if (newFindingGenericVuln != null
				&& newFindingGenericVuln.getId() != null
				&& oldFindingGenericVuln != null
				&& oldFindingGenericVuln.getId() != null
				&& newFindingGenericVuln.getId().equals(
						oldFindingGenericVuln.getId())) {

			// check to see that they have the same path
			if (newFinding.getSurfaceLocation() != null
					&& oldFinding.getSurfaceLocation() != null) {
				if (newFinding.getSurfaceLocation().getPath() != null
						&& oldFinding.getSurfaceLocation().getPath() != null
						&& newFinding
								.getSurfaceLocation()
								.getPath()
								.equals(oldFinding.getSurfaceLocation()
										.getPath())) {

					// check to see that the parameters match or are both
					// missing
					if (newFinding.getSurfaceLocation().getParameter() == null
							&& oldFinding.getSurfaceLocation().getParameter() == null)
						return true;
					else if (newFinding.getSurfaceLocation().getParameter() != null
							&& newFinding
									.getSurfaceLocation()
									.getParameter()
									.equals(oldFinding.getSurfaceLocation()
											.getParameter()))
						return true;
					// if the code reaches this point the findings are in the
					// same location but have
					// different parameters and should be treated as different
					// vulnerabilities.
				}
			}
		}

		return false;
	}

	// Not all dataFlowElements have Column Numbers, and the default is 0,
	// so it is hard to do a meaningful comparison with that data. Plus, we
	// compared variables before starting the rest of the static-static
	// comparison.
	// TODO look at changing this comparison
	private boolean compareDataFlowElements(DataFlowElement oldElement,
			DataFlowElement newElement) {
		if (oldElement == null || newElement == null)
			return false;

		return sourceFileNameCompare(oldElement.getSourceFileName(),
				newElement.getSourceFileName())
				&& oldElement.getLineNumber() == newElement.getLineNumber();
	}

	// Compare the relative paths according to the application's projectRoot
	// variable.
	private boolean sourceFileNameCompare(String fileName1, String fileName2) {
		if (fileName1 == null || fileName1.trim().equals("")
				|| fileName2 == null || fileName2.equals(""))
			return false;

		String path1 = cleanPathString(fileName1);
		String path2 = cleanPathString(fileName2);

		// if for some reason cleaning the paths failed, compare the uncleaned
		// paths.
		if (path1 == null || path1.trim().equals("") || path2 == null
				|| path2.trim().equals(""))
			return fileName1.equals(fileName2);

		// if we don't have a project root, or it isn't in one of the paths,
		// return normal comparison of the cleaned strings.
		if (projectRoot == null || projectRoot.trim().equals("")
				|| !path1.contains(projectRoot) || !path2.contains(projectRoot))
			return path1.equals(path2);

		// if we do have it and it is in both paths, compare the relative paths
		if (path1.contains(projectRoot) && path2.contains(projectRoot)) {
			return path1.substring(path1.indexOf(projectRoot)).equals(
					path2.substring(path2.indexOf(projectRoot)));
		}

		return false;
	}

	// we want to compare strings that have been lowercased, have had
	// their leading / removed, and have / or \ all pointing the same way.
	private String cleanPathString(String inputString) {
		if (inputString == null || inputString.trim().equals(""))
			return null;
		String outputString = inputString.toLowerCase();

		if (outputString.contains("\\"))
			outputString = outputString.replace("\\", "/");

		if (outputString.charAt(0) == '/')
			outputString = outputString.substring(1);

		return outputString;
	}

	/**
	 * Find the hashed vulnerability ID(s) and put them into a vulnerability
	 * object.
	 * 
	 * THIS METHOD REQUIRES THE CHANNEL VULN AND EITHER PARAMETER OR PATH TO
	 * ALREADY BE SET
	 * 
	 * @param finding
	 * @param param
	 * @param vulnList
	 * @param genericVulnerabilityDao
	 * @return
	 */
	private Vulnerability parseVulnerability(Finding finding) {
		if (finding == null) {
			log.warn("Unable to parse a vulnerability due to a null Finding.");
			return null;
		}

		if (finding.getChannelVulnerability() == null) {
			log.debug("The finding did not have a ChannelVulnerability so no vulnerability could be parsed.");
			return null;
		}

		if (genericVulnerabilityDao == null) {
			log.error("genericVulnerabilityDao has not been configured so no vulnerability could be parsed.");
			return null;
		}

		String locationVariableHash = null, locationHash = null, variableHash = null;
		ChannelVulnerability cv = null;
		GenericVulnerability genericVulnerability = null;

		if (finding.getChannelVulnerability() != null)
			cv = finding.getChannelVulnerability();

		if (cv != null
				&& cv.getVulnerabilityMaps() != null
				&& cv.getVulnerabilityMaps().size() > 0
				&& cv.getVulnerabilityMaps().get(0) != null
				&& cv.getVulnerabilityMaps().get(0).getGenericVulnerability() != null)
			genericVulnerability = cv.getVulnerabilityMaps().get(0)
					.getGenericVulnerability();

		// TODO write to log
		if (genericVulnerability == null
				|| genericVulnerability.getName() == null
				|| genericVulnerability.getName().trim().equals("")) {

			if (cv != null) {
				log.debug("No generic vulnerability was found for the Channel Vulnerability with code "
						+ cv.getCode());
			}
			return null;
		}

		Vulnerability vulnerability = new Vulnerability();
		vulnerability.openVulnerability(Calendar.getInstance());
		vulnerability.setGenericVulnerability(genericVulnerability);
		vulnerability.setSurfaceLocation(finding.getSurfaceLocation());

		if (finding.isMarkedFalsePositive()) {
			log.info("Creating a false positive vulnerability from a finding marked false positive.");
			vulnerability.setIsFalsePositive(finding.isMarkedFalsePositive());
		}

		String vulnName = genericVulnerability.getName();

		if (finding.getChannelSeverity() != null) {
			vulnerability.setGenericSeverity(getGenericSeverity(finding
					.getChannelSeverity()));
		}

		String param = null;
		if (finding.getSurfaceLocation() != null) {
			param = finding.getSurfaceLocation().getParameter();
		}

		if (finding.getSurfaceLocation() != null
				&& finding.getSurfaceLocation().getPath() != null
				&& !finding.getSurfaceLocation().getPath().equals("")) {
			if (param != null) {
				// if we get here, all three variables are present. Hash all of
				// them.
				locationVariableHash = hashFindingInfo(vulnName, finding
						.getSurfaceLocation().getPath(), param);
				locationHash = hashFindingInfo(vulnName, finding
						.getSurfaceLocation().getPath(), null);
				variableHash = hashFindingInfo(vulnName, null, param);
				vulnerability.setLocationVariableHash(locationVariableHash);
				vulnerability.setLocationHash(locationHash);
				vulnerability.setVariableHash(variableHash);
				return vulnerability;
			} else {
				// if we get here, we just have location and CWE.
				locationHash = hashFindingInfo(vulnName, finding
						.getSurfaceLocation().getPath(), null);
				vulnerability.setLocationHash(locationHash);
				return vulnerability;
			}
		} else if (param != null) {
			// if we get here, we have variable and CWE
			variableHash = hashFindingInfo(vulnName, null, param);
			vulnerability.setVariableHash(variableHash);
			return vulnerability;
		} else {
			log.warn("The finding had neither path nor parameter and no vulnerability could be parsed.");
			return null;
		}
	}

	private GenericVulnerability getGenericVulnerability(
			ChannelVulnerability channelVulnerability) {
		if (channelVulnerability == null
				|| channelVulnerability.getVulnerabilityMaps() == null
				|| channelVulnerability.getVulnerabilityMaps().size() == 0
				|| channelVulnerability.getVulnerabilityMaps().get(0) == null
				|| channelVulnerability.getVulnerabilityMaps().get(0)
						.getGenericVulnerability() == null)
			return null;
		return channelVulnerability.getVulnerabilityMaps().get(0)
				.getGenericVulnerability();
	}

	/**
	 * @param cs
	 * @return
	 */
	private GenericSeverity getGenericSeverity(ChannelSeverity cs) {
		GenericSeverity severity = null;

		if (cs != null && cs.getSeverityMap() != null)
			severity = cs.getSeverityMap().getGenericSeverity();

		return severity;
	}

	/**
	 * Hashes whatever three strings are given to it.
	 * 
	 * @param type
	 *            The generic, CWE type of vulnerability.
	 * @param url
	 *            The URL location of the vulnerability.
	 * @param param
	 *            The vulnerable parameter (optional)
	 * @throws NoSuchAlgorithmException
	 *             Thrown if the MD5 algorithm cannot be found.
	 * @return The three strings concatenated, downcased, trimmed, and hashed.
	 */
	private String hashFindingInfo(String type, String url, String param) {
		StringBuffer toHash = new StringBuffer();

		if (type != null) {
			toHash = toHash.append(type.toLowerCase().trim());
		}

		if (url != null) {
			if (url.indexOf('/') == 0 || url.indexOf('\\') == 0) {
				toHash = toHash.append(url.substring(1).toLowerCase().trim());
			} else {
				toHash = toHash.append(url.toLowerCase().trim());
			}
		}

		if (param != null) {
			toHash = toHash.append(param.toLowerCase().trim());
		}

		try {
			MessageDigest messageDigest = MessageDigest.getInstance("MD5");
			messageDigest.update(toHash.toString().getBytes(), 0,
					toHash.length());
			return new BigInteger(1, messageDigest.digest()).toString(16);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * This method has a lot of code duplication with processScanFile(). We
	 * should consolidate.
	 */
	@Override
	public Scan processRemoteScan(Scan scan) {

		if (scan == null) {
			log.warn("The remote import failed.");
			return null;
		}

		ApplicationChannel applicationChannel = scan.getApplicationChannel();

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
			return scan;
		}

		projectRoot = null;
		findOrParseProjectRoot(applicationChannel, scan);
		channelMerge(scan, applicationChannel);
		appMerge(scan, applicationChannel.getApplication().getId(), null);

		scan.setApplicationChannel(applicationChannel);
		scan.setApplication(applicationChannel.getApplication());

		if (scan.getNumberTotalVulnerabilities() != null
				&& scan.getNumberNewVulnerabilities() != null)
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed processing with "
					+ scan.getNumberTotalVulnerabilities()
					+ " total Vulnerabilities ("
					+ scan.getNumberNewVulnerabilities() + " new).");
		else
			log.info(applicationChannel.getChannelType().getName()
					+ " scan completed.");

		cleanFindings(scan);
		processFindings(scan);
		scanDao.saveOrUpdate(scan);

		return scan;
	}

	/**
	 * @param status
	 */
	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}
}
