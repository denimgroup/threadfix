package com.denimgroup.threadfix.service.report;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanCloseVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanReopenVulnerabilityMap;

/**
 * The current strategy for this report is to keep Sets of the vulnerability IDs
 * representing the new / old / reopened vulns for each month.
 * All the collected scans are iterated through, following this process:
 * <br>
 * <br>Vulns are added to the new vuln set if the scan contains the first finding for the vuln.
 * <br>If a vuln is reopened by a scan, it is added to the reopened set.
 * <br>At the end of every month, all vulns are moved to the old vulns set for future months.
 * <br>If a vuln is closed by a scan, it is removed from all three sets.
 * <br>
 * <br>For each month, this method should yield counts for:
 * <br>All the new vulns that weren't also closed in the same month,
 * <br>The number of old vulnerabilities from previous months still open at the end of the month,
 * <br>And the number of vulnerabilities that resurfaced and were still open at the end of the month.
 * 
 * @author mcollins
 *
 */
public class JasperMonthlyScanReport implements JRDataSource {
	private List<Scan> scanList = new ArrayList<>();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<>();

	private List<Scan> normalizedScans = new ArrayList<>();
	
	Set<Integer> newVulns = new HashSet<>(),
			 	 oldVulns = new HashSet<>(),
			 	 reopenedVulns = new HashSet<>();

	public JasperMonthlyScanReport(List<Integer> applicationIdList,
			ScanDao scanDao) {
		if (scanDao != null && applicationIdList != null) {
			this.scanList = scanDao
					.retrieveByApplicationIdList(applicationIdList);
		}
		
		if (this.scanList != null && this.scanList.size() > 0) {
			Collections.sort(this.scanList, Scan.getTimeComparator());
	
			normalizeForMonths();
		}
		
		index = -1;
	}

	private void normalizeForMonths() {
		newVulns.clear();
		oldVulns.clear();
		reopenedVulns.clear();
		
		int previousYear = -1, previousMonth = -1;
		Scan currentScan = null;
		
		for (Scan scan : this.scanList) {
			if (previousYear == -1) {
				// Start the process off with all new vulns from the first scan.
				previousYear = scan.getImportTime().get(Calendar.YEAR);
				previousMonth = scan.getImportTime().get(Calendar.MONTH);
				
				initializeSets(scan);
				currentScan = scan;
				
			} else {
				
				adjustSets(scan);
				
				if (scan.getImportTime().get(Calendar.YEAR) != previousYear
						|| scan.getImportTime().get(Calendar.MONTH) != previousMonth) {
					addScanToReportList(currentScan);
					
					moveAllToOld();
										
					// add a new current entry
					previousYear = scan.getImportTime().get(Calendar.YEAR);
					previousMonth = scan.getImportTime().get(Calendar.MONTH);
					
					currentScan = scan;
				}
			}
		}
		
		// include the last scan
		addScanToReportList(currentScan);
		
		insertEmptyScans(normalizedScans);
	}
	
	/**
	 * Set initial set contents
	 * @param scan
	 */
	private void initializeSets(Scan scan) {
		if (scan == null || scan.getFindings() == null) {
			return;
		}
		
		for (Finding finding : scan.getFindings()) {
			if (finding == null || finding.getVulnerability() == null || finding.getVulnerability().getHidden()) {
				continue;
			}

			newVulns.add(finding.getVulnerability().getId());
		}
	}
	
	// At the end of each month, all existing vulns are old vulns
	private void moveAllToOld() {
		oldVulns.addAll(newVulns);
		oldVulns.addAll(reopenedVulns);
		newVulns.clear();
		reopenedVulns.clear();
	}

	// adjust the counts based on new Scan contents
	private void adjustSets(Scan scan) {
		if (scan != null) {
			// if the scan closes a vuln, remove it from all fields
			if (scan.getScanCloseVulnerabilityMaps() != null &&
					!scan.getScanCloseVulnerabilityMaps().isEmpty()) {
				for (ScanCloseVulnerabilityMap map : scan.getScanCloseVulnerabilityMaps()) {
					if (!map.getVulnerability().getHidden()) {
						newVulns.remove(map.getVulnerability().getId());
						oldVulns.remove(map.getVulnerability().getId());
						reopenedVulns.remove(map.getVulnerability().getId());
					}
				}
			}
			
			// if the scan reopens a vuln, add it to that count.
			if (scan.getScanReopenVulnerabilityMaps() != null &&
					!scan.getScanReopenVulnerabilityMaps().isEmpty()) {
				for (ScanReopenVulnerabilityMap map : scan.getScanReopenVulnerabilityMaps()) {
					if (!map.getVulnerability().getHidden()) {
						reopenedVulns.add(map.getVulnerability().getId());
					}
				}
			}
			
			// if there are any new vulns introduced by the scan, add those to the new vulns.
			if (scan.getFindings() != null) {
				for (Finding finding : scan.getFindings()) {
					if (finding.isFirstFindingForVuln() && finding.getVulnerability() != null &&
							!finding.getVulnerability().getHidden()) {
						newVulns.add(finding.getVulnerability().getId());
					}
				}
			}
		}
	}
	
	// adjust the scan numbers and add it to the list
	// the adjusted scan numbers are not and should not be saved
	private void addScanToReportList(Scan currentScan) {
		currentScan.setNumberOldVulnerabilities(oldVulns.size());
		currentScan.setNumberNewVulnerabilities(newVulns.size());
		currentScan.setNumberResurfacedVulnerabilities(reopenedVulns.size());
		normalizedScans.add(currentScan);
	}
	
	// in order to get the bars to show up we need to add empty scans
	private void insertEmptyScans(List<Scan> scanList) {

		Scan previousScan = null;
		List<Scan> scansToInsert = new ArrayList<>();

		for (Scan scan : scanList) {
			if (previousScan == null) {
				previousScan = scan;
				continue;
			}
			if (scan.getImportTime().after(previousScan.getImportTime())
					&& (scan.getImportTime().get(Calendar.YEAR) != previousScan
							.getImportTime().get(Calendar.YEAR) || scan
							.getImportTime().get(Calendar.MONTH) != previousScan
							.getImportTime().get(Calendar.MONTH))) {
				scansToInsert.addAll(getScansBetween(previousScan, scan));
			}
			previousScan = scan;
		}

		scanList.addAll(scansToInsert);
		Collections.sort(scanList, Scan.getTimeComparator());
	}

	// skipping null checks for now
	private List<Scan> getScansBetween(Scan firstScan, Scan secondScan) {
		List<Scan> betweenScans = new ArrayList<>();

		Scan tempScan = firstScan;

		while (true) {
			if (secondScan.getImportTime().after(tempScan.getImportTime())
					&& (secondScan.getImportTime().get(Calendar.YEAR) != tempScan
							.getImportTime().get(Calendar.YEAR) || secondScan
							.getImportTime().get(Calendar.MONTH) != tempScan
							.getImportTime().get(Calendar.MONTH))) {

				Calendar newCalendar = Calendar.getInstance();
				newCalendar.setTime(tempScan.getImportTime().getTime());
				newCalendar.add(Calendar.MONTH, 1);

				if (secondScan.getImportTime().after(newCalendar)
						&& (secondScan.getImportTime().get(Calendar.YEAR) != newCalendar
								.get(Calendar.YEAR) || secondScan
								.getImportTime().get(Calendar.MONTH) != newCalendar
								.get(Calendar.MONTH))) {
					Scan newScan = new Scan();
					newScan.setNumberClosedVulnerabilities(0);
					newScan.setNumberNewVulnerabilities(0);
					newScan.setNumberResurfacedVulnerabilities(0);
					newScan.setNumberOldVulnerabilities(firstScan.getNumberOldVulnerabilities() +
														firstScan.getNumberNewVulnerabilities() +
														firstScan.getNumberResurfacedVulnerabilities());
					newScan.setNumberOldVulnerabilitiesInitiallyFromThisChannel(0);
					newScan.setNumberTotalVulnerabilities(0);
					newScan.setImportTime(newCalendar);
					betweenScans.add(newScan);
					tempScan = newScan;
				} else {
					break;
				}
			} else {
				break;
			}
		}

		return betweenScans;
	}

	@Override
	public Object getFieldValue(JRField field) {
		if (field == null) {
			return null;
		}
		String name = field.getName();
		if (name == null) {
			return null;
		}

		if (resultsHash.containsKey(name)) {
			return resultsHash.get(name);
		} else {
			return null;
		}
	}

	@Override
	public boolean next() {
		if (normalizedScans != null && index < normalizedScans.size() - 1) {
			if (index == -1) {
				index = 0;
			} else {
				index++;
			}
			buildHash();
			return true;
		} else {
			return false;
		}
	}

	private void buildHash() {
		resultsHash.clear();

		Scan scan = normalizedScans.get(index);

		resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
		resultsHash.put("resurfacedVulns",
				scan.getNumberResurfacedVulnerabilities());
		resultsHash.put("oldVulns", scan.getNumberOldVulnerabilities());

		if (scan.getApplication() != null
				&& scan.getApplication().getName() != null) {
			resultsHash.put("name", scan.getApplication().getName());
		}

		if (scan.getImportTime() != null) {
			resultsHash.put("importTime", scan.getImportTime());
		}

	}

}
