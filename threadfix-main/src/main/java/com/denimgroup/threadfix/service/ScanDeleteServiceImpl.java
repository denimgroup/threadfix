package com.denimgroup.threadfix.service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityCommentDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanCloseVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanReopenVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.VulnerabilityComment;
import com.denimgroup.threadfix.data.entities.WafRule;

@Service
@Transactional(readOnly = false)
public class ScanDeleteServiceImpl implements ScanDeleteService {
	
	private final SanitizedLogger log = new SanitizedLogger("ScanDeleteService");

	private ScanDao scanDao = null;
	private VulnerabilityDao vulnerabilityDao = null;
	private VulnerabilityCommentDao vulnerabilityCommentDao = null;
	private FindingDao findingDao = null;
	private WafRuleDao wafRuleDao = null;
	private DefectDao defectDao = null;

	@Autowired
	public ScanDeleteServiceImpl(ScanDao scanDao,
			VulnerabilityDao vulnerabilityDao,
			VulnerabilityCommentDao vulnerabilityCommentDao,
			FindingDao findingDao, WafRuleDao wafRuleDao,
			DefectDao defectDao) {
		this.scanDao = scanDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.findingDao = findingDao;
		this.wafRuleDao = wafRuleDao;
		this.defectDao = defectDao;
		this.vulnerabilityCommentDao = vulnerabilityCommentDao;
	}
	
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
		
		log.info("The scan deletion has finished.");
	}
	
	/**
	 * This method is used when a scan's vulns should update their status based on 
	 * their presence in the next scan in the sequence.
	 * @param scan
	 * @param nextScan
	 */
	private void updateVulnStatusWithNextScan(Scan scan, Scan nextScan) {
		
		List<ScanCloseVulnerabilityMap> closeMapsToDelete = 
			new ArrayList<>();
		List<ScanReopenVulnerabilityMap> reopenMapsToDelete = 
			new ArrayList<>();
		
		List<ScanCloseVulnerabilityMap> closeMapsToRemove = 
			new ArrayList<>();
		List<ScanReopenVulnerabilityMap> reopenMapsToRemove = 
			new ArrayList<>();

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
					vulnerabilityDao.saveOrUpdate(closeMap.getVulnerability());
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
					vulnerabilityDao.saveOrUpdate(reopenMap.getVulnerability());
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
							
							if (closeMap != null && closeMap.getScan() != null && 
									closeMap.getScan().getImportTime() != null) {
								vuln.setCloseTime(closeMap.getScan().getImportTime());
							}
						}
					}

					// TODO else if there are more older maps, change the close time to 
					// what it was before
					vuln.getScanCloseVulnerabilityMaps().remove(map);
					if (map.getVulnerability().isFoundByScanner()) {
						vuln.openVulnerability(map.getVulnerability().getOpenTime());
					}
					vulnerabilityDao.saveOrUpdate(vuln);
				}
			}
		}
		
		if (scan != null && scan.getScanReopenVulnerabilityMaps() != null) {
			for (ScanReopenVulnerabilityMap map : scan.getScanReopenVulnerabilityMaps()) {
				if (map != null && map.getVulnerability() != null) {

					if (map.getVulnerability().isFoundByScanner()) {
						map.getVulnerability().closeVulnerability(null, null);
					}
					map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
					vulnerabilityDao.saveOrUpdate(map.getVulnerability());
				}
			}
		}
	}
	
	private void updateRepeatFindings(Scan scan, Scan scanToDelete) {
		if (scan == null || scan.getId() == null || 
				scanToDelete == null || scanToDelete.getId() == null) {
			return;
		}
		
		if (scan.getScanRepeatFindingMaps() != null
				&& scan.getScanRepeatFindingMaps().size() > 0) {
				List<ScanRepeatFindingMap> mapsToRemove = new ArrayList<>();
				
				for (ScanRepeatFindingMap map : scan.getScanRepeatFindingMaps()) {
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
			vulnerabilityDao.saveOrUpdate(earliestFinding.getVulnerability());
		
			if (finding != null && !earliestFinding.getId().equals(finding.getId())) {
				// set it to be the first finding
				finding.setFirstFindingForVuln(false);
				findingDao.saveOrUpdate(finding);
			}
			
			log.debug("Updating new / old vuln stats for the Scan with ID " + 
					earliestFinding.getScan().getId());
			
			earliestFinding.getScan().setNumberNewVulnerabilities(
					earliestFinding.getScan().getNumberNewVulnerabilities() + 1);
			earliestFinding.getScan().setNumberOldVulnerabilities(
					earliestFinding.getScan().getNumberOldVulnerabilities() - 1);
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
				new ArrayList<>();
			List<ScanReopenVulnerabilityMap> reopenMapsToDelete = 
				new ArrayList<>();
			List<Vulnerability> vulnsToUpdate = new ArrayList<>();
			
			if (scan.getScanCloseVulnerabilityMaps() != null) {
				for (ScanCloseVulnerabilityMap map : scan.getScanCloseVulnerabilityMaps()) {
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
				updateVulnStatus(vuln);
			}
			
			
			if (closeMapsToDelete.size() > 0) {
				for (ScanCloseVulnerabilityMap map : closeMapsToDelete) {
					scan.getScanCloseVulnerabilityMaps().remove(map);
					map.getVulnerability().getScanCloseVulnerabilityMaps().remove(map);
					scanDao.deleteMap(map);
					vulnerabilityDao.saveOrUpdate(map.getVulnerability());
				}
				scanDao.saveOrUpdate(scan);
			}
			
			if (reopenMapsToDelete.size() > 0) {
				for (ScanReopenVulnerabilityMap map : reopenMapsToDelete) {
					scan.getScanReopenVulnerabilityMaps().remove(map);
					map.getVulnerability().getScanReopenVulnerabilityMaps().remove(map);
					scanDao.deleteMap(map);
					vulnerabilityDao.saveOrUpdate(map.getVulnerability());
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
		List<Finding> findingsToRemove = new ArrayList<>();
		List<Vulnerability> vulnsToRemove = new ArrayList<>();
		
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
				
				if (newFirstFinding == null || earliestTime == null ||
						(finding.getScan().getImportTime() != null 
						 && finding.getScan().getImportTime().before(earliestTime))) {
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
				updateVulnDates(vuln, scan);
				if (vuln.getOriginalFinding() == null || 
						vuln.getOriginalFinding().getScan().getId().equals(scan.getId())) {
					updateFirstFindingForVuln(null,vuln);
				}
				// be sure to save in case there's any updated state
				vulnerabilityDao.saveOrUpdate(vuln);
			}
		}
		
		for (Vulnerability vuln : vulnsToRemove) {
			log.debug("Deleting vulnerability with ID " + vuln.getId());
			app.getVulnerabilities().remove(vuln);
			
			// Since WAF Rules can only have one vulnerability, just delete them.
			if (vuln.getWafRules() != null && vuln.getWafRules().size() > 0) {
				for (WafRule wafRule : vuln.getWafRules()) {
					log.debug("Deleting WAF Rule with ID " + wafRule.getId() 
							+ " because it was attached to the Vulnerability with ID " + vuln.getId());
					wafRuleDao.delete(wafRule);
				}
			}
			
			if (vuln.getVulnerabilityComments() != null && !vuln.getVulnerabilityComments().isEmpty()) {
				for (VulnerabilityComment comment : vuln.getVulnerabilityComments()) {
					vulnerabilityCommentDao.delete(comment);
				}
			}
			
			// We need to check to see if the associated Defect has any valid vulns still
			// attached to it before deleting.
			if (vuln.getDefect() != null && 
					vuln.getDefect().getVulnerabilities() != null) {
				boolean keepIt = false;
				for (Vulnerability loopVuln : vuln.getDefect().getVulnerabilities()) {
					if (loopVuln.getFindings() != null && 
							loopVuln.getFindings().size() != 0) {
						keepIt = true;
						break;
					}
				}
				if (!keepIt) {
					log.debug("Deleting orphaned defect with ID " + vuln.getDefect().getId() + ".");
					defectDao.delete(vuln.getDefect());
				}
			}
			
			// Vulns should not have any reopen maps if they are here
			// but they can have close maps.
			if (vuln.getScanCloseVulnerabilityMaps() != null) {
				for (ScanCloseVulnerabilityMap map : vuln.getScanCloseVulnerabilityMaps()) {
					map.getScan().getScanCloseVulnerabilityMaps().remove(map);
					map.getScan().setNumberClosedVulnerabilities(
							map.getScan().getNumberClosedVulnerabilities() - 1);
					scanDao.deleteMap(map);
					scanDao.saveOrUpdate(map.getScan());
				}
			}
			
			vulnerabilityDao.delete(vuln);
		}
	}

	/**
	 * Sets open and close times for the vuln based on the current set of
	 * close and reopen maps.
	 * @param vuln
	 * @param scanToDelete
	 */
	private void updateVulnDates(Vulnerability vuln, Scan scanToDelete) {
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
			new ArrayList<>();
		List<ScanReopenVulnerabilityMap> reopenMapsToRemove = 
			new ArrayList<>();
	
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
				
				if (!vuln.isActive() || newCloseTime.before(newOpenTime)) {
					vuln.openVulnerability(newOpenTime);
				}
				
				if (vuln.isActive() || newCloseTime.after(newOpenTime)) {
					vuln.closeVulnerability(null, newCloseTime);
				}
			}
			vuln.setOpenTime(newOpenTime);
			vulnerabilityDao.saveOrUpdate(vuln);
		}
	}
	
	/**
	 * Sets open and close times for the vuln based on the current set of
	 * close and reopen maps.
	 * @param vuln
	 * @param scanToDelete
	 */
	private void updateVulnStatus(Vulnerability vuln) {
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
			vuln.openVulnerability(newOpenTime);
		}
		
		if (vuln.isActive() && newCloseTime != null &&
				newCloseTime.after(newOpenTime)) {
			vuln.closeVulnerability(null, newCloseTime);
		}
		vulnerabilityDao.saveOrUpdate(vuln);
	}
	
}
