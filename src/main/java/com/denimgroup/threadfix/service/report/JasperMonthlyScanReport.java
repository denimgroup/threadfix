package com.denimgroup.threadfix.service.report;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Scan;

public class JasperMonthlyScanReport implements JRDataSource {
	private List<Scan> scanList = new ArrayList<Scan>();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<String, Object>();

	private List<Scan> normalizedScans = new ArrayList<Scan>();
	
	private Map<Integer, Integer> channelIdOldVulnCountHash = new HashMap<Integer, Integer>();

	public JasperMonthlyScanReport(List<Integer> applicationIdList,
			ScanDao scanDao) {
		if (scanDao != null && applicationIdList != null)
			this.scanList = scanDao
					.retrieveByApplicationIdList(applicationIdList);

		Collections.sort(this.scanList, Scan.getTimeComparator());

		normalizeForMonths();

		index = -1;
	}

	public void normalizeForMonths() {
		int previousYear = -1, previousMonth = -1;
		Scan currentScan = null;

		for (Scan scan : this.scanList) {
			if (previousYear == -1) {
				currentScan = scan;
				previousYear = scan.getImportTime().get(Calendar.YEAR);
				previousMonth = scan.getImportTime().get(Calendar.MONTH);
				addToHash(currentScan);
			} else {
				if (scan.getImportTime().get(Calendar.YEAR) == previousYear
						&& scan.getImportTime().get(Calendar.MONTH) == previousMonth) {
					// Merge the two scans

				} else {
					// Add the previous one to the list
					finalizeScan(currentScan);
					
					// add a new current entry
					currentScan = scan;
					previousYear = scan.getImportTime().get(Calendar.YEAR);
					previousMonth = scan.getImportTime().get(Calendar.MONTH);
					addToHash(currentScan);
				}
			}
		}
		
		insertEmptyScans(normalizedScans);
	}
	
	public void addToHash(Scan initialScan) {
		if (initialScan.getApplicationChannel() != null && initialScan.getApplicationChannel().getId() != null) {
            Integer appChannelId = initialScan.getApplicationChannel().getId();
            channelIdOldVulnCountHash.put(appChannelId, initialScan.getNumberOldVulnerabilitiesInitiallyFromThisChannel());
		}
	}
	
	public void merge(Scan scan, Scan scanToMerge) {
		if (scanToMerge.getApplicationChannel() != null && scanToMerge.getApplicationChannel().getId() != null) {
            Integer appChannelId = scanToMerge.getApplicationChannel().getId();
            channelIdOldVulnCountHash.put(appChannelId, scanToMerge.getNumberOldVulnerabilitiesInitiallyFromThisChannel());
		}
		
		scan.setNumberNewVulnerabilities(scanToMerge.getNumberNewVulnerabilities() + scan.getNumberNewVulnerabilities());
		scan.setNumberResurfacedVulnerabilities(scanToMerge.getNumberResurfacedVulnerabilities() + scan.getNumberResurfacedVulnerabilities());
	}
	
	public void finalizeScan(Scan currentScan) {
		int total = 0;
		for (Integer number : channelIdOldVulnCountHash.values()) {
			total += number;
		}
		currentScan.setNumberOldVulnerabilities(total);
		
		normalizedScans.add(currentScan);
	}
	
	
	public void insertEmptyScans(List<Scan> scanList) {

		Scan previousScan = null;
		List<Scan> scansToInsert = new ArrayList<Scan>();

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
	public List<Scan> getScansBetween(Scan firstScan, Scan secondScan) {
		List<Scan> betweenScans = new ArrayList<Scan>();

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
					newScan.setNumberOldVulnerabilities(firstScan.getNumberOldVulnerabilities());
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
		if (field == null)
			return null;
		String name = field.getName();
		if (name == null)
			return null;

		if (resultsHash.containsKey(name))
			return resultsHash.get(name);
		else
			return null;
	}

	@Override
	public boolean next() {
		if (scanList != null && index < scanList.size() - 1) {
			if (index == -1)
				index = 0;
			else
				index++;
			buildHash();
			return true;
		} else
			return false;
	}

	public void buildHash() {
		resultsHash.clear();

		Scan scan = scanList.get(index);

		resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
		resultsHash.put("resurfacedVulns",
				scan.getNumberResurfacedVulnerabilities());
		resultsHash.put("oldVulns", scan.getNumberOldVulnerabilities()
									- scan.getNumberResurfacedVulnerabilities());

		if (scan.getApplication() != null
				&& scan.getApplication().getName() != null)
			resultsHash.put("name", scan.getApplication().getName());

		if (scan.getImportTime() != null)
			resultsHash.put("importTime", scan.getImportTime());

	}

}
