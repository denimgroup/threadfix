package com.denimgroup.threadfix.service;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public class ApplicationScanMerger {
	
	public final ApplicationDao applicationDao;
	public final ScanDao scanDao;
	public final JobStatusService jobStatusService;
	
	public ApplicationScanMerger(ApplicationDao applicationDao,
			ScanDao scanDao,
			JobStatusService jobStatusService) {
		this.jobStatusService = jobStatusService;
		this.applicationDao = applicationDao;
		this.scanDao = scanDao;
	}
	
	private final SanitizedLogger log = new SanitizedLogger(ApplicationScanMerger.class);

	/**
	 * This method is in here to allow passing an application id when the application isn't already in the session.
	 * @param scan
	 * @param applicationId
	 * @param statusId
	 */
	public void applicationMerge(Scan scan, int applicationId, Integer statusId) {
		applicationMerge(scan, applicationDao.retrieveById(applicationId), statusId);
	}

	/**
	 * This method does the actual vulnerability merging across the app.
	 * 
	 * @param scan
	 * @param application
	 * @param statusId
	 */
	public void applicationMerge(Scan scan, Application application, Integer statusId) {
		
		FindingMatcher matcher = FindingMatcher.getBasicMatcher(application);
		
		updateJobStatus(statusId, "Channel merge completed. Starting application merge.");
		
		int initialOld = 0, numUnableToParseVuln = 0, numMergedInsideScan = 0;
		
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
				match = matcher.doesMatch(finding, vuln);
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
					match = matcher.doesMatch(finding, newVuln);
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
			log.warn("The finding did not have a ChannelVulnerability so no vulnerability could be parsed.");
			return null;
		}

		String locationVariableHash = null, locationHash = null, variableHash = null;
		GenericVulnerability genericVulnerability = null;
		
		boolean hasChannelVuln = finding != null && finding.getChannelVulnerability() != null;

		if (hasChannelVuln) {
			genericVulnerability = finding.getChannelVulnerability().getGenericVulnerability();
		}

		if (genericVulnerability == null
				|| genericVulnerability.getName() == null
				|| genericVulnerability.getName().trim().equals("")) {

			if (hasChannelVuln) {
				log.debug("No generic vulnerability was found for the Channel Vulnerability with code "
						+ finding.getChannelVulnerability().getCode());
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
	
	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}
}
