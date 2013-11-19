package com.denimgroup.threadfix.service.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * This class provides the data source for the Trending Report.
 * @author mcollins
 *
 */
public class JasperScanReport implements JRDataSource {
	private List<Scan> scanList = new ArrayList<>();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<>();
	private Map<Integer, Integer> oldVulnsByChannelMap = new HashMap<>();
	
	public JasperScanReport(List<Integer> applicationIdList, ScanDao scanDao) {
		if (scanDao != null && applicationIdList != null)
			this.scanList = scanDao.retrieveByApplicationIdList(applicationIdList);
				
		Collections.sort(this.scanList, Scan.getTimeComparator());

		index = -1;
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
			if (index == -1) {
				index = 0;
			} else {
				index++;
			}
			buildHash();
			return true;
		}
		else
			return false;
	}
	
	private void buildHash() {
		Scan scan = scanList.get(index);
		
		if (scan == null) {
			return;
		}
					
		resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
		resultsHash.put("resurfacedVulns", scan.getNumberResurfacedVulnerabilities());
		
		if (scan.getImportTime() != null)
			resultsHash.put("importTime", scan.getImportTime());
		
		// Take out from the count old vulns from other channels.
		Integer adjustedTotal = scan.getNumberTotalVulnerabilities() -
								scan.getNumberOldVulnerabilities() +
								scan.getNumberOldVulnerabilitiesInitiallyFromThisChannel();
		
		Integer appChannelId = null;
		if (scan.getApplicationChannel() != null && scan.getApplicationChannel().getId() != null) {
			appChannelId = scan.getApplicationChannel().getId();

			oldVulnsByChannelMap.put(appChannelId, adjustedTotal);
		}
		
		Integer numTotal = adjustedTotal;
		
		// This code counts in the old vulns from other channels.
		for (Integer key : oldVulnsByChannelMap.keySet()) {
			if (key == null || oldVulnsByChannelMap.get(key) == null || 
					(appChannelId != null && appChannelId.equals(key)))
				continue;
			numTotal += oldVulnsByChannelMap.get(key);
		}
		
		resultsHash.put("totVulns", numTotal);
	}

}
