////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.JobStatusService;

import java.util.Calendar;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * This class is used to remove all the logging code from the merging code.
 * @author mcollins
 *
 */
public class ScanStatisticsUpdater {
	
	private final static SanitizedLogger log = new SanitizedLogger(ScanStatisticsUpdater.class);
	
	private Scan scan;
	private Set<Vulnerability> alreadySeenVulns = set();
	private ScanDao scanDao;
	private JobStatusService jobStatusService;
	private int numMergedInsideScan = 0, initialOld = 0, numUnableToParseVuln = 0;
	private Integer statusId;
	
	private long interval = 0, count = 0, soFar = 0;
	private boolean logging = false;

	public ScanStatisticsUpdater(Scan scan, ScanDao scanDao, JobStatusService jobStatusService,
			Integer statusId) {
		this.scan = scan;
		this.jobStatusService = jobStatusService;
		this.scanDao = scanDao;
		this.statusId = statusId;
		
		updateJobStatus(statusId, "Starting application merge.");
		
		log.info("Starting Application-wide merge process with "
				+ scan.getFindings().size() + " findings.");
		
		if (scan.getNumberOldVulnerabilities() == null) {
			scan.setNumberOldVulnerabilities(0);
		}
		initialOld = scan.getNumberOldVulnerabilities();
		
		interval = scan.getFindings().size() / 10;
		
		if (scan.getFindings().size() > 10000) {
			logging = true;
			log.info("The scan has more than 10,000 findings, ThreadFix will print a message every "
					+ interval + " (~10%) findings processed.");
		}
	}
	
	/**
	 * This method is intended to be used at the start of each iteration
	 * of the finding loop.
	 */
	public void doFindingCountUpdate() {
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
	}
	
	/**
	 * This method is supposed to be used when a finding is matched to a vulnerability
	 * that was constructed from a finding in the new scan that's being merged. Both
	 * Findings will have the same scan and vulnerability.
	 * @param finding
	 */
	public void addFindingToInScanVulnUpdate(Finding finding) {
		finding.setFirstFindingForVuln(false);
		
		numMergedInsideScan += 1;
		
		scan.setNumberTotalVulnerabilities(scan
				.getNumberTotalVulnerabilities() - 1);
		scan.setNumberNewVulnerabilities(scan
				.getNumberNewVulnerabilities() - 1);
	}
	
	/**
	 * This method is supposed to be used when a finding is added to a new vulnerability.
	 * The vulnerability will have just been constructed using the finding.
	 * @param finding
	 */
	public void addFindingToNewVulnUpdate(Finding finding, Vulnerability newVuln) {
		if (newVuln == null) {
			numUnableToParseVuln += 1;
			scan.setNumberTotalVulnerabilities(scan
					.getNumberTotalVulnerabilities() - 1);
			scan.setNumberNewVulnerabilities(scan
					.getNumberNewVulnerabilities() - 1);
		}
	}
	
	/**
	 * This method is supposed to be used when a finding is matched to an old vulnerability.
	 * Findings will have different scans and the same vulnerability.
	 * @param finding
	 */
	public void addFindingToOldVulnUpdate(Finding finding, Vulnerability vuln) {
		finding.setFirstFindingForVuln(false);

		// Again, we don't want to count old vulns that we match
		// against more than once so we keep track of those using a hash.
		if (alreadySeenVulns.contains(vuln)) {
			scan.setNumberNewVulnerabilities(scan.getNumberNewVulnerabilities() - 1);
			scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities() - 1);

			return;
		}

		// if we get here we're adding the finding to a vulnerability not already associated with this scan
		alreadySeenVulns.add(vuln);

		// we correct this later if it's actually a new vulnerability already in the database with a later timestamp
		scan.setNumberNewVulnerabilities(scan.getNumberNewVulnerabilities() - 1);
		scan.setNumberOldVulnerabilities(scan.getNumberOldVulnerabilities() + 1);

		// pulling these into variables makes the code easier to follow
		Finding previousOriginalFinding = vuln.getOriginalFinding();

		Scan previousOriginalScan = previousOriginalFinding.getScan();
		Calendar previousOriginalScanDate = previousOriginalScan.getImportTime();

		ApplicationChannel
				thisChannel = scan.getApplicationChannel(),
				previousOriginalChannel = previousOriginalScan.getApplicationChannel();

		boolean isSameScanner = false;

		if (thisChannel != null && previousOriginalChannel != null && thisChannel.getId() != null) {
			isSameScanner = thisChannel.getId().equals(previousOriginalChannel.getId());
		}

		if (isSameScanner) {

			// must be an older scan from the same channel
			scan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(this.scan
					.getNumberOldVulnerabilitiesInitiallyFromThisChannel() + 1);

			scan.setNumberOldVulnerabilities(scan.getNumberOldVulnerabilities() + 1);

		} else {
			if (previousOriginalScanDate.after(scan.getImportTime())) {

				// if we got here, that means the original finding for the vuln was from a later scan
				// from a different scanner, which means we need to increase our number of new stuff and
				// remove from that scan.
				finding.setFirstFindingForVuln(true);

				// this corrects the lines above
				scan.setNumberNewVulnerabilities(scan.getNumberNewVulnerabilities() + 1);
				scan.setNumberOldVulnerabilities(scan.getNumberOldVulnerabilities() - 1);

				correctExistingScans(previousOriginalFinding);
			}
		}
	}

	/**
	 * This method corrects newer scans that were uploaded first in a different
	 * channel. The finding parameter is the finding that used to be the original finding
	 * so we need to decrement its scan's new count and increase its old count
	 * 
	 */
	private void correctExistingScans(Finding finding) {
		finding.getVulnerability().setSurfaceLocation(
				finding.getVulnerability().getOriginalFinding().getSurfaceLocation());
		finding.setFirstFindingForVuln(false);
		finding.getScan().setNumberNewVulnerabilities(
				finding.getScan().getNumberNewVulnerabilities() - 1);
		finding.getScan().setNumberOldVulnerabilities(
				finding.getScan().getNumberOldVulnerabilities() + 1);

		if (finding.getScanRepeatFindingMaps() != null) {
			for (ScanRepeatFindingMap map : finding.getScanRepeatFindingMaps()) {
				if (map.getScan() != null && map.getScan()
						.getNumberOldVulnerabilitiesInitiallyFromThisChannel() != null) {
					map.getScan().setNumberOldVulnerabilitiesInitiallyFromThisChannel(
						map.getScan().getNumberOldVulnerabilitiesInitiallyFromThisChannel() - 1);
				}
			}
		}

		scanDao.saveOrUpdate(finding.getScan());
	}
	

	private void updateJobStatus(Integer statusId, String statusString) {
		if (statusId != null) {
			jobStatusService.updateJobStatus(statusId, statusString);
		}
	}
}
