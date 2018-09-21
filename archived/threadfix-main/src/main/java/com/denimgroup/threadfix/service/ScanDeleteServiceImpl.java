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

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nullable;
import java.io.File;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listFrom;
import static com.denimgroup.threadfix.CollectionUtils.set;

@Service
@Transactional(readOnly = false)
public class ScanDeleteServiceImpl implements ScanDeleteService {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanDeleteService");

    @Autowired
	private ScanDao scanDao;
    @Autowired
	private VulnerabilityService vulnerabilityService;
	@Autowired
	private VulnerabilityStatusService vulnerabilityStatusService;
    @Autowired
	private VulnerabilityCommentDao vulnerabilityCommentDao;
    @Autowired
	private FindingDao findingDao;
    @Autowired
	private WafRuleDao wafRuleDao;
    @Autowired
	private DefectDao defectDao;
	@Autowired
	private EndpointPermissionService endpointPermissionService;
    @Autowired
    private DefaultConfigService defaultConfigService;
    @Nullable
    @Autowired(required = false)
    private PolicyStatusService policyStatusService;

	private DefaultConfiguration defaultConfiguration;
	@Autowired
	private StatisticsCounterDao statisticsCounterDao;

	/**
	 * Deleting a scan requires a lot of code to check and make sure that all mappings
	 * are where they should be. A lot of this is facilitated by ScanReopenVulnerabilityMap
	 * and ScanCloseVulnerabilityMap, which allow us to see which scans opened and closed 
	 * which vulns, and ScanRepeatFindingMap, which allows us to see when a finding was found
	 * in other scans. The basic strategy is to figure out the status that each vulnerability 
	 * in the scan to delete should have, then update the mappings to reflect that.
	 * 
	 * TODO maybe refactor this stuff 
	 * TODO add more logging, maybe at debug level
	 */
	@Override
	public void deleteScan(Scan scan) {

		defaultConfiguration = defaultConfigService.loadCurrentConfiguration();

		// if the scan is missing one of these it is probably malformed
		if (scan == null || scan.getApplication() == null
				|| scan.getApplicationChannel() == null
				|| scan.getApplicationChannel().getChannelType() == null) {
			return;
		}

		log.info("Deleting scan with ID " + scan.getId());
		
		ChannelType type = scan.getApplicationChannel().getChannelType();
		
		if (scan.getApplication().getRemoteProviderApplications() != null) {
			for (RemoteProviderApplication app : scan.getApplication().getRemoteProviderApplications()) {
				if (app != null && app.getRemoteProviderType() != null &&
						app.getRemoteProviderType().getChannelType() != null &&
						app.getRemoteProviderType().getChannelType().getId() != null &&
						app.getRemoteProviderType().getChannelType().getId().equals(type.getId()) &&
						app.getLastImportTime() != null && scan.getImportTime() != null && 
						app.getLastImportTime().equals(scan.getImportTime()) &&
						app.getApplicationChannel() != null && app.getApplicationChannel().getScanList() != null){
					// This means that we are deleting the last scan for the importer and that we need to update the
					// last import time so that we can import more scans.
					
					Calendar latestTime = null;
					for (Scan remoteScan : app.getApplicationChannel().getScanList()) {
						if (!remoteScan.getId().equals(scan.getId()) && (latestTime == null ||
								latestTime.before(scan.getImportTime()))) {
							latestTime = remoteScan.getImportTime();
						}
					}
					app.setLastImportTime(latestTime);
				}
			}
		}
		
		Integer scanId = scan.getId();
		Integer scanApplicationChannelId = scan.getApplicationChannel().getId();
		Application app = scan.getApplication();
		List<Scan> appScanList = app.getScans();
		
		if (scanId == null || scanApplicationChannelId == null || appScanList == null) {
			// also probably malformed
			return;
		}
		
		Collections.sort(appScanList, Scan.getTimeComparator());
		
		boolean afterScan = false, immediatelyAfterScan = false;
		
		// relocate any findings that have been found in other scans
		for (Scan appScan : appScanList) {
			if (afterScan && appScan != null
					&& appScan.getApplicationChannel() != null
					&& appScan.getApplicationChannel().getId() != null
					&& scanApplicationChannelId.equals(
							appScan.getApplicationChannel().getId())) {
				
				if (immediatelyAfterScan) {
					log.info("Moving findings to next scan in sequence and updating status.");
					// Check the status of each vuln and update any close / reopen maps
					updateVulnStatusWithNextScan(scan, appScan);
					immediatelyAfterScan = false;
				}
				
				log.info("Updating repeat finding maps for scan with ID " + appScan.getId() + ".");
				// Delete repeat mappings and move findings
				updateRepeatFindings(appScan, scan);
			}

			// We don't want to mess with anything in scans before the scan being deleted
			// so the afterScan flag will mark when we should and should not process scans.
			if (!afterScan && appScan != null && appScan.getId().equals(scanId)) {
				afterScan = true;
				immediatelyAfterScan = true;
			}
		}
		
		if (immediatelyAfterScan) {
			log.info("The scan being deleted was the most recent.");
			// If there are no scans after the one being deleted then the open / closed
			// status is determined by the previous scans instead of the next one.
			processLastScanDeletion(scan);
		}
		
		log.info("About to update vulnerabilities and delete any that " +
					"will be orphaned after this scan deletion.");

		// update the vulnerabilities
		deleteOrphanVulnerabilities(app, scan);
		
		log.info("Running consistency check on scans.");
		// Now that we have the updated scan, we can check over close and reopen maps and 
		// make sure they come in an order that makes sense.
		correctScanStatistics(appScanList, scan);

		scanDao.deleteFindingsAndScan(scan);

        // If file upload location exists and file associated with scan exists, delete file
        if (defaultConfiguration.fileUploadLocationExists()) {
            String filePath = defaultConfiguration.getFullFilePath(scan);
            File file = new File(filePath);
            if (file.exists() && !file.delete()) {
                log.warn("Something went wrong trying to delete the file.");

                file.deleteOnExit();
            } else {
                log.info("Deleted file at location: " + filePath);
            }
        }

        // Run status check on delete
        if (policyStatusService != null) {
            policyStatusService.runStatusCheck(app);
        }

		log.info("The scan deletion has finished.");

	}
	
	/**
	 * This method is used when a scan's vulns should update their status based on 
	 * their presence in the next scan in the sequence.
	 * @param scan
	 * @param nextScan
	 */
	private void updateVulnStatusWithNextScan(Scan scan, Scan nextScan) {
		
		List<ScanCloseVulnerabilityMap> closeMapsToDelete = list();
		List<ScanReopenVulnerabilityMap> reopenMapsToDelete = list();
		
		List<ScanCloseVulnerabilityMap> closeMapsToRemove = list();
		List<ScanReopenVulnerabilityMap> reopenMapsToRemove = list();

		// First check to see if any closed vulns were reopened
		if (scan.getScanCloseVulnerabilityMaps() != null) {
			CLOSE: for (ScanCloseVulnerabilityMap closeMap : scan.getScanCloseVulnerabilityMaps()) {
				if (nextScan.getScanReopenVulnerabilityMaps() != null) {
					for (ScanReopenVulnerabilityMap reopenMap : 
							nextScan.getScanReopenVulnerabilityMaps()) {
						if (closeMap.getVulnerability().getId().equals(
								reopenMap.getVulnerability().getId())) {
							// If they were, delete the mappings and leave the vuln
							// with the status it had
							reopenMapsToDelete.add(reopenMap);
							nextScan.setNumberResurfacedVulnerabilities(
									nextScan.getNumberResurfacedVulnerabilities() - 1);
							scanDao.saveOrUpdate(nextScan);
							continue CLOSE;
						}
					}
					
					// if we get here, the finding wasn't found in the scan
					// so we should move the closeMap to this scan
					closeMap.setScan(nextScan);
					nextScan.setNumberClosedVulnerabilities(
							nextScan.getNumberClosedVulnerabilities() + 1);
					closeMap.getVulnerability().setCloseTime(
							nextScan.getImportTime());
					closeMapsToRemove.add(closeMap);
					nextScan.getScanCloseVulnerabilityMaps().add(closeMap);
					vulnerabilityService.storeVulnerability(closeMap.getVulnerability());
					scanDao.saveOrUpdate(nextScan);
				}
			}
		}
		
		// check to see if any reopened vulns were closed
		if (scan.getScanReopenVulnerabilityMaps() != null) {
			REOPEN: for (ScanReopenVulnerabilityMap reopenMap : scan.getScanReopenVulnerabilityMaps()) {
				if (nextScan.getScanCloseVulnerabilityMaps() != null) {
					for (ScanCloseVulnerabilityMap closeMap : 
							nextScan.getScanCloseVulnerabilityMaps()) {
						if (reopenMap.getVulnerability().getId().equals(
								closeMap.getVulnerability().getId())) {
							// If they were, delete the mappings and leave the vuln
							// with the status it had
							closeMapsToDelete.add(closeMap);
							nextScan.setNumberClosedVulnerabilities(
									nextScan.getNumberClosedVulnerabilities() - 1);
							scanDao.saveOrUpdate(nextScan);
							continue REOPEN;
						}
					}
					
					// if we get here, the finding was not closed in the scan
					// so we should move the reopenMap to this scan
					// This logic fails if the vuln resurfaced in another channel
					reopenMap.setScan(nextScan);
					nextScan.setNumberResurfacedVulnerabilities(
							nextScan.getNumberResurfacedVulnerabilities() + 1);
					nextScan.getScanReopenVulnerabilityMaps().add(reopenMap);
					reopenMapsToRemove.add(reopenMap);
					scanDao.saveOrUpdate(nextScan);
					
					// TODO maybe down the road change this to resurface time or something
					reopenMap.getVulnerability().setOpenTime(
							nextScan.getImportTime());
					vulnerabilityService.storeVulnerability(reopenMap.getVulnerability());
				}
			}
		}

		// delete / remove appropriate maps
		for (ScanCloseVulnerabilityMap map : closeMapsToDelete) {
			map.getScan().getScanCloseVulnerabilityMaps().remove(map);
			map.getVulnerability().getScanCloseVulnerabilityMaps().remove(map);
			scanDao.deleteMap(map);
		}

		for (ScanReopenVulnerabilityMap map : reopenMapsToDelete) {
			map.getScan().getScanReopenVulnerabilityMaps().remove(map);
			map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
			
			scanDao.deleteMap(map);
		}

		for (ScanCloseVulnerabilityMap map : closeMapsToRemove) {
			scan.getScanCloseVulnerabilityMaps().remove(map);
		}

		for (ScanReopenVulnerabilityMap map : reopenMapsToRemove) {
			scan.getScanReopenVulnerabilityMaps().remove(map);
		}
	}
	
	/**
	 * This scan looks through ScanCloseVulnerabilityMaps and reopens them with
	 * their previous state and looks through ScanReopenVulnerabilityMaps and closes the vulns
	 * with their previous state. This method is only called if the scan was the last scan in 
	 * the channel because otherwise the status of all vulns is determined by the next scan
	 * in the channel.
	 * 
	 * @param scan
	 */
	private void processLastScanDeletion(Scan scan) {

		boolean immediatelyOpen = true;

		if (scan != null && scan.getScanCloseVulnerabilityMaps() != null) {
			for (ScanCloseVulnerabilityMap map : scan.getScanCloseVulnerabilityMaps()) {
				if (map != null && map.getVulnerability() != null) {
					
					Vulnerability vuln = map.getVulnerability();

					if (vuln.getScanCloseVulnerabilityMaps() != null) {
						if (vuln.getScanCloseVulnerabilityMaps().size() == 1) {
							vuln.setCloseTime(null);
						} else if (vuln.getScanCloseVulnerabilityMaps().size() > 1) {

							ScanCloseVulnerabilityMap closeMap = vuln.getScanCloseVulnerabilityMaps()
												.get(vuln.getScanCloseVulnerabilityMaps().size() - 2);

							immediatelyOpen = !defaultConfiguration.getCloseVulnWhenNoScannersReport();

							if (closeMap != null && closeMap.getScan() != null &&
									closeMap.getScan().getImportTime() != null) {
								vuln.setCloseTime(closeMap.getScan().getImportTime());
							}
						}
					}

					// TODO else if there are more older maps, change the close time to 
					// what it was before
					vuln.getScanCloseVulnerabilityMaps().remove(map);
					if (map.getVulnerability().isFoundByScanner() && immediatelyOpen) {
						vulnerabilityStatusService.openVulnerability(vuln, scan, null, map.getVulnerability().getOpenTime(), true, false);
					}
					vulnerabilityService.storeVulnerability(vuln);
					scanDao.deleteMap(map);
					map.setVulnerability(null);
					map.setScan(null);
				}
			}
			scan.getScanCloseVulnerabilityMaps().clear();
		}
		
		if (scan != null && scan.getScanReopenVulnerabilityMaps() != null) {
			for (ScanReopenVulnerabilityMap map : scan.getScanReopenVulnerabilityMaps()) {
				if (map != null && map.getVulnerability() != null) {

					if (map.getVulnerability().isFoundByScanner()) {
						vulnerabilityStatusService.closeVulnerability(map.getVulnerability(), scan, null, true, false);
					}
					map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
					vulnerabilityService.storeVulnerability(map.getVulnerability());
					scanDao.deleteMap(map);
					map.setVulnerability(null);
					map.setScan(null);
				}
			}
			scan.getScanReopenVulnerabilityMaps().clear();
		}
	}
	
	private void updateRepeatFindings(Scan scan, Scan scanToDelete) {
		if (scan == null || scan.getId() == null || 
				scanToDelete == null || scanToDelete.getId() == null) {
			return;
		}
		
		if (scan.getScanRepeatFindingMaps() != null
				&& scan.getScanRepeatFindingMaps().size() > 0) {
				List<ScanRepeatFindingMap> mapsToRemove = list();

			List<ScanRepeatFindingMap> scanCopy = listFrom(scan.getScanRepeatFindingMaps());

			for (ScanRepeatFindingMap map : scanCopy) {
				if (map != null && map.getFinding() != null
						&& map.getFinding().getScan() != null
						&& map.getFinding().getScan().getId() != null
						&& map.getFinding().getScan().getId().equals(scanToDelete.getId())) {

					log.debug("Moving Finding with ID " + map.getFinding().getId() +
							" to scan with ID " + scan.getId() + " and deleting mapping.");
					scan.setNumberRepeatFindings(scan.getNumberRepeatFindings() -1);
					scan.setNumberRepeatResults(
							scan.getNumberRepeatResults() -
							map.getFinding().getNumberMergedResults());
					scan.getFindings().add(map.getFinding());
					map.getFinding().getScan().getFindings().remove(map.getFinding());
					map.getFinding().setScan(scan);
					mapsToRemove.add(map);

					updateFirstFindingForVuln(map.getFinding(),
							map.getFinding().getVulnerability());
				}
			}
				
			scan.getScanRepeatFindingMaps().removeAll(mapsToRemove);
			for (ScanRepeatFindingMap map : mapsToRemove) {
				map.getFinding().getScanRepeatFindingMaps().remove(map);
				map.getScan().getScanRepeatFindingMaps().remove(map);

				// Update scanId of StatisticsCounter of scan to delete
				List<StatisticsCounter> counters = listFrom(map.getFinding().getStatisticsCounters());
					for (StatisticsCounter counter: counters) {
						if (counter.getScanRepeatFindingMap() != null
								&& counter.getScanRepeatFindingMap().getId().compareTo(map.getId()) == 0) {
							map.getFinding().getStatisticsCounters().remove(counter);
						} else if (counter.getScanId().compareTo(scanToDelete.getId()) == 0) {
							counter.setScanId(scan.getId());
						}
					}

				scanDao.saveOrUpdate(map.getScan());
				findingDao.saveOrUpdate(map.getFinding());
				scanDao.deleteMap(map);
			}
		}
	}

	/**
	 * If it was the first finding for the vuln then
	 * both the vulnerability open time and the scan new vuln count need
	 * to be updated.
	 * 
	 * WARNING: don't call on any findings that haven't just been moved.
	 * 
	 * @param vuln
	 */
	private void updateFirstFindingForVuln(Finding finding, Vulnerability vuln) {
		if (finding != null && (!finding.isFirstFindingForVuln() || 
				finding.getVulnerability() == null || vuln == null)) {
			// it's ok - we don't need to update any mappings / dates / etc.
			return;
		}
		
		Finding earliestFinding = null;
		
		// High water mark algorithm for finding earliest finding
		for (Finding vulnFinding : vuln.getFindings()) {
			if (vulnFinding != null && vulnFinding.getScan() != null 
					&& (earliestFinding == null || 
							earliestFinding.getScan().getImportTime()
							.after(vulnFinding.getScan().getImportTime()))) {
				earliestFinding = vulnFinding;
			}
		}
		
		if (earliestFinding != null) {
			earliestFinding.getVulnerability().setSurfaceLocation(
					earliestFinding.getSurfaceLocation());
			earliestFinding.setFirstFindingForVuln(true);
			findingDao.saveOrUpdate(earliestFinding);
			vulnerabilityService.storeVulnerability(earliestFinding.getVulnerability());
		
			if (finding != null && !earliestFinding.getId().equals(finding.getId())) {
				// set it to be the first finding
				finding.setFirstFindingForVuln(false);
				findingDao.saveOrUpdate(finding);
			}
			
			log.debug("Updating new / old vuln stats for the Scan with ID " + 
					earliestFinding.getScan().getId());
			
            if (earliestFinding.getScan().getNumberOldVulnerabilities() > 0) {
                earliestFinding.getScan().setNumberNewVulnerabilities(
                        earliestFinding.getScan().getNumberNewVulnerabilities() + 1);
                earliestFinding.getScan().setNumberOldVulnerabilities(
                        earliestFinding.getScan().getNumberOldVulnerabilities() - 1);
            }
			scanDao.saveOrUpdate(earliestFinding.getScan());
			
			vuln.setOpenTime(earliestFinding.getScan().getImportTime());
		}
		
	}	
	/**
	 * Remove any maps for vulns that didn't yet exist or reopen mappings for a scan
	 * which now holds the first instance of the vuln
	 * @param scanList
	 * @param toDelete
	 */
	private void correctScanStatistics(List<Scan> scanList, Scan toDelete) {
		if (scanList == null || toDelete == null) {
			return;
		}
		
		for (Scan scan : scanList) {
			if (!scan.getImportTime().after(toDelete.getImportTime())) {
				continue;
			}
			
			List<ScanCloseVulnerabilityMap> closeMapsToDelete = 
				list();
			List<ScanReopenVulnerabilityMap> reopenMapsToDelete = 
				list();
			List<Vulnerability> vulnsToUpdate = list();
			
			if (scan.getScanCloseVulnerabilityMaps() != null) {

				List<ScanCloseVulnerabilityMap> scanCloseVulnerabilityMapsCopy = listFrom(scan.getScanCloseVulnerabilityMaps());

				for (ScanCloseVulnerabilityMap map : scanCloseVulnerabilityMapsCopy) {
					if (map != null && map.getVulnerability() != null &&
							map.getVulnerability().getOriginalFinding() != null 
							&& map.getVulnerability().getOriginalFinding().getScan() != null 
							&& map.getVulnerability().getOriginalFinding().getScan().getImportTime()
								.after(scan.getImportTime())) {
						closeMapsToDelete.add(map);
						scan.setNumberClosedVulnerabilities(
								scan.getNumberClosedVulnerabilities() - 1);
						scanDao.saveOrUpdate(scan);
					}
					
					// A channel may have lingering invalid close maps if the vulnerability no
					// longer has any findings from its channel. Let's close those if they're there.
					if (map != null && map.getVulnerability() != null &&
							map.getVulnerability().getFindings() != null) {
						boolean isInChannel = false;
						for (Finding finding : map.getVulnerability().getFindings()) {
							if (finding != null && finding.getScan() != null &&
									finding.getScan().getApplicationChannel() != null &&
									finding.getScan().getApplicationChannel().getId().equals(
											scan.getApplicationChannel().getId())) {
								isInChannel = true;
							}
						}
						
						if (!isInChannel) {
							closeMapsToDelete.add(map);
							scan.setNumberClosedVulnerabilities(
									scan.getNumberClosedVulnerabilities() - 1);
							vulnsToUpdate.add(map.getVulnerability());
							scanDao.saveOrUpdate(scan);
						}
					}
				}
			}
			
			if (scan.getScanReopenVulnerabilityMaps() != null) {
				for (ScanReopenVulnerabilityMap map : scan.getScanReopenVulnerabilityMaps()) {
					if (map != null && map.getVulnerability() != null &&
							map.getVulnerability().getOriginalFinding() != null 
							&& map.getVulnerability().getOriginalFinding().getScan() != null 
							&& !map.getVulnerability().getOriginalFinding().getScan().getImportTime()
								.before(scan.getImportTime())) {
						reopenMapsToDelete.add(map);
						scan.setNumberResurfacedVulnerabilities(
								scan.getNumberResurfacedVulnerabilities() - 1);
						
					}
				}
			}

			for (Vulnerability vuln : vulnsToUpdate) {
				vuln.getScanCloseVulnerabilityMaps().removeAll(closeMapsToDelete);
				updateVulnStatus(vuln, scan);
			}


			if (closeMapsToDelete.size() > 0) {
				for (ScanCloseVulnerabilityMap map : closeMapsToDelete) {
					scan.getScanCloseVulnerabilityMaps().remove(map);
					map.getVulnerability().getScanCloseVulnerabilityMaps().remove(map);
					scanDao.deleteMap(map);
					vulnerabilityService.storeVulnerability(map.getVulnerability());
				}
				scanDao.saveOrUpdate(scan);
			}

			if (reopenMapsToDelete.size() > 0) {
				for (ScanReopenVulnerabilityMap map : reopenMapsToDelete) {
					scan.getScanReopenVulnerabilityMaps().remove(map);
					map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
					scanDao.deleteMap(map);
					vulnerabilityService.storeVulnerability(map.getVulnerability());
				}
				scanDao.saveOrUpdate(scan);
			}
		}
	}
	


	/**
	 * This method checks through the vulnerabilities and makes sure that any 
	 * orphaned vulnerabilities are deleted and that the "first finding" 
	 * status of vulns is correctly updated.
	 * 
	 * This functionality is similar to updateRepeatFindings() but works cross-channel
	 * 
	 * @param app
	 * @param scan
	 */
	private void deleteOrphanVulnerabilities(Application app, Scan scan) {
		List<Finding> findingsToRemove = list();
		Set<Vulnerability> vulnsToRemove = set();

		// Cycle through vulns and update
		if (app.getVulnerabilities() == null || app.getVulnerabilities().size() == 0) {
			return;
		}
		
		for (Vulnerability vuln : app.getVulnerabilities()) {
			if (vuln == null) continue;
			// if there are no findings then delete - this shouldn't happen
			if (vuln.getFindings() == null || vuln.getFindings().size() == 0) {
				vulnsToRemove.add(vuln);
			}

			findingsToRemove.clear();

			// Remove any findings from the scan being deleted and 
			// update the first finding for reporting purposes
			boolean changeFirstFinding = false;
			Finding newFirstFinding = null;
			Calendar earliestTime = null;
			for (Finding finding : vuln.getFindings()) {
				if (finding == null || finding.getScan() == null
						|| finding.getScan().getId() == null) {
					continue;
				}

				if ((newFirstFinding == null || earliestTime == null ||
						(finding.getScan().getImportTime() != null
								&& finding.getScan().getImportTime().before(earliestTime)))
						&& !finding.getScan().getId().equals(scan.getId())) {
					newFirstFinding = finding;
					earliestTime = finding.getScan().getImportTime();
				}

				if (finding.getScan().getId().equals(scan.getId())) {
					finding.setVulnerability(null);
					findingsToRemove.add(finding);
					if (finding.isFirstFindingForVuln()) {
						changeFirstFinding = true;
					}
				}
			}

			// Should avoid any problems related to removing items from a collection
			// while iterating through it.
			vuln.getFindings().removeAll(findingsToRemove);

			if (changeFirstFinding && newFirstFinding != null) {
				if (newFirstFinding.getVulnerability() != null) {
					newFirstFinding.getVulnerability().setSurfaceLocation(
							newFirstFinding.getSurfaceLocation());
				}

				newFirstFinding.setFirstFindingForVuln(true);
				log.debug("Updating number new vulnerabilities for Scan with ID " +
						newFirstFinding.getScan().getId());
				newFirstFinding.getScan().setNumberNewVulnerabilities(
						newFirstFinding.getScan().getNumberNewVulnerabilities() + 1);

				vuln.setOpenTime(newFirstFinding.getScan().getImportTime());
			}

			// now if the vuln has no findings, delete it
			if (vuln.getFindings().size() == 0) {
				vulnsToRemove.add(vuln);

			} else {
				// Update severity to vuln if the higher severity findings are removed
				GenericSeverity highestRemovedFindingSeverity = getHighestGenericSeverity(findingsToRemove);
				GenericSeverity highestRemainFindingSeverity = getHighestGenericSeverity(vuln.getFindings());
				GenericSeverity currentVulnSeverity = vuln.getGenericSeverity();

				if (currentVulnSeverity == null) {
					ChannelSeverity original = vuln.getOriginalFinding() == null ? null :
							vuln.getOriginalFinding().getChannelSeverity();

					log.error("Got a null vuln severity--this is bad. " +
							"The finding's channel severity was " + original);
				}

				if (currentVulnSeverity != null && currentVulnSeverity.getIntValue() != null &&
						highestRemovedFindingSeverity != null &&
						currentVulnSeverity.getIntValue() == highestRemovedFindingSeverity.getIntValue()) {
					vuln.setGenericSeverity(highestRemainFindingSeverity);
				}

				updateVulnDates(vuln, scan, defaultConfiguration.getCloseVulnWhenNoScannersReport() == null ?
						false : defaultConfiguration.getCloseVulnWhenNoScannersReport());
				if (vuln.getOriginalFinding() == null ||
						vuln.getOriginalFinding().getScan().getId().equals(scan.getId())) {
					updateFirstFindingForVuln(null, vuln);
				}
				// be sure to save in case there's any updated state
				vulnerabilityService.storeVulnerability(vuln);
			}
		}

		for (Vulnerability vuln : vulnsToRemove) {
			log.debug("Deleting vulnerability with ID " + vuln.getId());
			app.getVulnerabilities().remove(vuln);
			
			// Since WAF Rules can only have one vulnerability, just delete them.
			List<WafRule> wafRules = vuln.getWafRules();
			if (wafRules != null && wafRules.size() > 0) {
				for (WafRule wafRule : wafRules) {
					log.debug("Deleting WAF Rule with ID " + wafRule.getId() 
							+ " because it was attached to the Vulnerability with ID " + vuln.getId());
					wafRuleDao.delete(wafRule);
				}
				wafRules = list();
				vuln.setWafRules(wafRules);
			}
			
			if (vuln.getVulnerabilityComments() != null && !vuln.getVulnerabilityComments().isEmpty()) {
				for (VulnerabilityComment comment : vuln.getVulnerabilityComments()) {
					vulnerabilityCommentDao.delete(comment);
				}
			}
			
			vuln.setDefect(null);

			// Vulns should not have any reopen maps if they are here
			// but they can have close maps.
			if (vuln.getScanCloseVulnerabilityMaps() != null) {
				List<ScanCloseVulnerabilityMap> vulnMapCopy = listFrom(vuln.getScanCloseVulnerabilityMaps());
				for (ScanCloseVulnerabilityMap map : vulnMapCopy) {
					if (scan.getScanCloseVulnerabilityMaps().contains(map)) {
						scan.getScanCloseVulnerabilityMaps().remove(map);
						scan.setNumberClosedVulnerabilities(
								scan.getNumberClosedVulnerabilities() - 1);
					} else {
						map.getScan().getScanCloseVulnerabilityMaps().remove(map);
						map.getScan().setNumberClosedVulnerabilities(scan.getNumberClosedVulnerabilities() - 1);
					}

					vuln.getScanCloseVulnerabilityMaps().remove(map);

					scanDao.deleteMap(map);
					map.setVulnerability(null);
					map.setScan(null);

				}
			}

			for (EndpointPermission permission : vuln.getEndpointPermissions()) {
				permission.getVulnerabilityList().remove(vuln);
				endpointPermissionService.saveOrUpdate(permission);
			}

			vulnerabilityService.deleteVulnerability(vuln);
		}
	}

	private GenericSeverity getHighestGenericSeverity(List<Finding> findings) {
		if (findings == null || findings.size() == 0)
			return null;

		if (findings.get(0).getChannelSeverity() != null
				&& findings.get(0).getChannelSeverity().getSeverityMap() != null
				&& findings.get(0).getChannelSeverity().getSeverityMap().getGenericSeverity() != null) {

			GenericSeverity returnSeverity = findings.get(0).getChannelSeverity().getSeverityMap().getGenericSeverity();

			for (Finding finding : findings) {
				if (finding.getChannelSeverity() != null
						&& finding.getChannelSeverity().getSeverityMap() != null
						&& finding.getChannelSeverity().getSeverityMap().getGenericSeverity() != null) {
					if (returnSeverity.getIntValue() < finding.getChannelSeverity().getSeverityMap().getGenericSeverity().getIntValue()) {
						returnSeverity = finding.getChannelSeverity().getSeverityMap().getGenericSeverity();
					}
				}
			}

			return returnSeverity;
		}

		return null;
	}

	/**
	 * Sets open and close times for the vuln based on the current set of
	 * close and reopen maps.
	 * @param vuln
	 * @param scanToDelete
	 */
	private void updateVulnDates(Vulnerability vuln, Scan scanToDelete, boolean closeVulnWhenNoScannersReport) {
		if (vuln == null || vuln.getFindings() == null ||
				vuln.getFindings().size() == 0 || scanToDelete == null ||
				scanToDelete.getId() == null) {
			return;
		}
		
		Calendar newOpenTime = null;
		Calendar newCloseTime = null;
	
		if (vuln.getOriginalFinding() != null
				&& vuln.getOriginalFinding().getScan() != null
				&& vuln.getOriginalFinding().getScan().getImportTime() != null) {
			newOpenTime = vuln.getOriginalFinding().getScan().getImportTime();
		}
		
		List<ScanCloseVulnerabilityMap> closeMapsToRemove = 
			list();
		List<ScanReopenVulnerabilityMap> reopenMapsToRemove = 
			list();
	
		// This ugly block should give the vuln the close date of the last scan close map
		// that it has.
		if (vuln.getScanCloseVulnerabilityMaps() != null) {
			for (ScanCloseVulnerabilityMap map : vuln.getScanCloseVulnerabilityMaps()) {
				if (map != null && map.getScan() != null
						&& map.getScan().getId().equals(scanToDelete.getId())) {
					closeMapsToRemove.add(map);
					continue;
				}
				
				if (map != null && map.getScan() != null &&
						map.getScan().getImportTime() != null &&
						(newCloseTime == null || newCloseTime.before(
								map.getScan().getImportTime()))) {
					newCloseTime = map.getScan().getImportTime();
				}
			}
		}
		
		// This ugly block should give the vuln the open date of the last scan Reopen map
		// that it has.
		if (vuln.getScanReopenVulnerabilityMaps() != null) {
			for (ScanReopenVulnerabilityMap map : vuln.getScanReopenVulnerabilityMaps()) {
				if (map != null && map.getScan() != null
						&& map.getScan().getId().equals(scanToDelete.getId())) {
					reopenMapsToRemove.add(map);
					continue;
				}
				
				if (map != null && map.getScan() != null && 
						map.getScan().getImportTime() != null &&
						(newOpenTime == null || 
								newOpenTime.before(map.getScan().getImportTime()))) {
					newOpenTime = map.getScan().getImportTime();
				}
			}
		}

		for (ScanCloseVulnerabilityMap map : closeMapsToRemove) {
			vuln.getScanCloseVulnerabilityMaps().remove(map);
		}

		for (ScanReopenVulnerabilityMap map : reopenMapsToRemove) {
			vuln.getScanReopenVulnerabilityMaps().remove(map);
		}
		
		if (newCloseTime != null && newOpenTime != null) {
			if (vuln.isFoundByScanner()) {
				vuln.setCloseTime(newCloseTime);

				// Calculate all the close maps from other channels other than the channel of scan to delete
				List<ScanCloseVulnerabilityMap> scanCloseVulnerabilityMaps = listFrom(vuln.getScanCloseVulnerabilityMaps());

				for (ScanCloseVulnerabilityMap map : vuln.getScanCloseVulnerabilityMaps()){
					if (scanToDelete.getApplicationChannel().getId() == map.getScan().getApplicationChannel().getId()) {
						scanCloseVulnerabilityMaps.remove(map);
					}
				}

				// If the time when it was (re)opened after the time when it was closed
				// and it is now found in this scanner (because we are deleting scan) then check the system setting of when to close a vulnerability
				if (!vuln.isActive() && newCloseTime.before(newOpenTime)
						&& (scanCloseVulnerabilityMaps.size() == 0 || closeVulnWhenNoScannersReport)) {
					vulnerabilityStatusService.openVulnerability(vuln, scanToDelete, null, newOpenTime, true, false);
				}

				boolean toClose = scanCloseVulnerabilityMaps.size() == 0 || (!closeVulnWhenNoScannersReport);
				if (vuln.isActive() && newCloseTime.after(newOpenTime) && toClose) {
					vulnerabilityStatusService.closeVulnerability(vuln, scanToDelete, newCloseTime, true, false);
				}
			}
			vuln.setOpenTime(newOpenTime);
			vulnerabilityService.storeVulnerability(vuln);
		}
	}
	
	/**
	 * Sets open and close times for the vuln based on the current set of
	 * close and reopen maps.
	 * @param vuln
	 */
	private void updateVulnStatus(Vulnerability vuln, Scan scanToDelete) {
		if (vuln == null || vuln.getFindings() == null ||
				!vuln.isFoundByScanner() ||
				vuln.getFindings().size() == 0) {
			return;
		}
		
		Calendar newOpenTime = null;
		Calendar newCloseTime = null;

		// This ugly block should give the vuln the close date of the last scan close map
		// that it has.
		if (vuln.getScanCloseVulnerabilityMaps() != null) {
			for (ScanCloseVulnerabilityMap map : vuln.getScanCloseVulnerabilityMaps()) {
				if (map != null && map.getScan() != null &&
						map.getScan().getImportTime() != null &&
						(newCloseTime == null || newCloseTime.before(
								map.getScan().getImportTime()))) {
					newCloseTime = map.getScan().getImportTime();
				}
			}
		}
		
		// This ugly block should give the vuln the open date of the last scan Reopen map
		// that it has.
		if (vuln.getScanReopenVulnerabilityMaps() != null) {
			for (ScanReopenVulnerabilityMap map : vuln.getScanReopenVulnerabilityMaps()) {
				if (map != null && map.getScan() != null && 
						map.getScan().getImportTime() != null &&
						(newOpenTime == null || 
								newOpenTime.before(map.getScan().getImportTime()))) {
					newOpenTime = map.getScan().getImportTime();
				}
			}
		}

		if (!vuln.isActive() && (newCloseTime == null || newOpenTime == null ||
				newCloseTime.before(newOpenTime))) {
			vulnerabilityStatusService.openVulnerability(vuln, scanToDelete, null, newOpenTime, true, false);
		}
		
		if (vuln.isActive() && newCloseTime != null &&
				newCloseTime.after(newOpenTime)) {
			vulnerabilityStatusService.closeVulnerability(vuln, scanToDelete, newCloseTime, true, false);
		}
		vulnerabilityService.storeVulnerability(vuln);
	}

	@Override
	public void deleteAllScanData(Application application) {
		Set<Defect> deletedDefects = set();
		for (Vulnerability vuln : application.getVulnerabilities()) {
			if (vuln.getVulnerabilityComments() != null && !vuln.getVulnerabilityComments().isEmpty()) {
				for (VulnerabilityComment comment : vuln.getVulnerabilityComments()) {
					vulnerabilityCommentDao.delete(comment);
				}
			}
			Defect defect = vuln.getDefect();
			if ((defect != null) && (!deletedDefects.contains(defect))) {
				defectDao.delete(defect);
				deletedDefects.add(defect);
			}
			for (ScanCloseVulnerabilityMap map : vuln.getScanCloseVulnerabilityMaps()) {
				map.setVulnerability(null);
				map.setScan(null);
				scanDao.deleteMap(map);
			}
			for (ScanReopenVulnerabilityMap map : vuln.getScanReopenVulnerabilityMaps()) {
				map.setVulnerability(null);
				map.setScan(null);
				scanDao.deleteMap(map);
			}

			for (Finding finding : vuln.getFindings()) {
				finding.setVulnerability(null);
			}

			for (WafRule wafRule : vuln.getWafRules()) {
				wafRule.setVulnerability(null);
			}

			vulnerabilityService.deleteVulnerability(vuln);
		}
		application.getVulnerabilities().clear();

		for (Scan scan : application.getScans()) {
			scanDao.deleteFindingsAndScan(scan);
		}
	}
	
}
