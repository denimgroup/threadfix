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
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.SanitizedLogger;

public class ChannelMerger extends SpringBeanAutowiringSupport {
	
	private final SanitizedLogger log = new SanitizedLogger(ChannelMerger.class);
	
	private VulnerabilityDao vulnerabilityDao;
	
	public ChannelMerger(VulnerabilityDao vulnerabilityDao) {
		this.vulnerabilityDao = vulnerabilityDao;
	}
	
	/**
	 * This is the first round of scan merge that only considers scans from the same scanner
	 * as the incoming scan.
	 * 
	 * @param scan
	 * @param applicationChannel
	 */
	public void channelMerge(Scan scan, ApplicationChannel applicationChannel) {
		if (scan == null || applicationChannel == null) {
			log.warn("Insufficient data to complete Application Channel-wide merging process.");
			return;
		}

		if (scan.getFindings() == null) {
			scan.setFindings(new ArrayList<Finding>());
		}

		List<Finding> oldFindings = new ArrayList<>();
		List<Finding> newFindings = new ArrayList<>();
		Map<String, Finding> scanHash = new HashMap<>();
		Map<String, Vulnerability> oldNativeIdVulnHash = new HashMap<>();
		Map<String, Finding> oldNativeIdFindingHash = new HashMap<>();
		Set<Integer> alreadySeenVulnIds = new TreeSet<>();
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
				&& applicationChannel.getScanList() != null) {
			for (Scan oldScan : applicationChannel.getScanList()) {
				if (oldScan != null && oldScan.getId() != null
						&& oldScan.getFindings() != null
						&& oldScan.getFindings().size() != 0) {
					oldFindings.addAll(oldScan.getFindings());
				}
			}
		}

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
				if (scan.getImportTime() != null) {
					oldNativeIdVulnHash.get(nativeId).closeVulnerability(scan,
							scan.getImportTime());
				} else {
					oldNativeIdVulnHash.get(nativeId).closeVulnerability(scan,
							Calendar.getInstance());
				}
				vulnerabilityDao.saveOrUpdate(oldNativeIdVulnHash.get(nativeId));
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
}
