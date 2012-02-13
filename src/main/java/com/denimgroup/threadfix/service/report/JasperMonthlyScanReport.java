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
	private Map<Integer, Integer> oldVulnsByChannelMap = new HashMap<Integer, Integer>();
			
	public JasperMonthlyScanReport(List<Integer> applicationIdList, ScanDao scanDao) {
		if (scanDao != null && applicationIdList != null)
			this.scanList = scanDao.retrieveByApplicationIdList(applicationIdList);

		Collections.sort(this.scanList, Scan.getTimeComparator());
		
		// Insert empty scans for the between months so that the monthly reporting doesn't skip any
		insertEmptyScans(this.scanList);
		
		Collections.sort(this.scanList, Scan.getTimeComparator());
		
		index = -1;
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
					&& (scan.getImportTime().get(Calendar.YEAR) != previousScan.getImportTime().get(Calendar.YEAR)
					|| scan.getImportTime().get(Calendar.MONTH) != previousScan.getImportTime().get(Calendar.MONTH))) {
				scansToInsert.addAll(getScansBetween(previousScan,scan));
			}
			previousScan = scan;
		}
		
		scanList.addAll(scansToInsert);
	}
	
	//skipping null checks for now
	public List<Scan> getScansBetween(Scan firstScan, Scan secondScan) {
		List<Scan> betweenScans = new ArrayList<Scan>();
		
		Scan tempScan = firstScan;
		
		while(true) {
			if (secondScan.getImportTime().after(tempScan.getImportTime())
					&& (secondScan.getImportTime().get(Calendar.YEAR) != tempScan.getImportTime().get(Calendar.YEAR)
					|| secondScan.getImportTime().get(Calendar.MONTH) != tempScan.getImportTime().get(Calendar.MONTH))) {
				
				Calendar newCalendar = Calendar.getInstance();
				newCalendar.setTime(tempScan.getImportTime().getTime());
				newCalendar.add(Calendar.MONTH, 1);
				
				if (secondScan.getImportTime().after(newCalendar)
						&& (secondScan.getImportTime().get(Calendar.YEAR) != newCalendar.get(Calendar.YEAR)
						|| secondScan.getImportTime().get(Calendar.MONTH) != newCalendar.get(Calendar.MONTH))) {
					Scan newScan = new Scan();
					newScan.setNumberClosedVulnerabilities(0);
					newScan.setNumberNewVulnerabilities(0);
					newScan.setNumberResurfacedVulnerabilities(0);
					newScan.setNumberOldVulnerabilities(0);
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
		if (field == null) return null;
		String name = field.getName();
		if (name == null) return null;

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
		}
		else
			return false;
	}
	
	private void buildHash() {
		Scan scan = scanList.get(index);
		
		if (scan == null)
			return;
					
		resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
		resultsHash.put("resurfacedVulns", scan.getNumberResurfacedVulnerabilities());

		if (scan.getApplication() != null && scan.getApplication().getName() != null)
			resultsHash.put("name", scan.getApplication().getName());
		
		if (scan.getImportTime() != null)
			resultsHash.put("importTime", scan.getImportTime());
		
		Integer appChannelId = null;
		if (scan.getApplicationChannel() != null && scan.getApplicationChannel().getId() != null) {
			appChannelId = scan.getApplicationChannel().getId();
			
			// Take out from the count old vulns from other channels.
			Integer adjustedTotal = scan.getNumberTotalVulnerabilities() -
									scan.getNumberOldVulnerabilities() +
									scan.getNumberOldVulnerabilitiesInitiallyFromThisChannel();
			
			oldVulnsByChannelMap.put(appChannelId, adjustedTotal);
		}
		
		// This code counts in the old vulns from other channels.
		Integer numOld = scan.getNumberOldVulnerabilitiesInitiallyFromThisChannel();
		if (numOld == null) numOld = 0;
		
		for (Integer key : oldVulnsByChannelMap.keySet()) {
			if (key == null || oldVulnsByChannelMap.get(key) == null || 
					(appChannelId != null && appChannelId.equals(key)))
				continue;
			numOld += oldVulnsByChannelMap.get(key);
		}
		
		resultsHash.put("oldVulns", numOld - scan.getNumberResurfacedVulnerabilities());
	}
}
