package com.denimgroup.threadfix.service.report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Scan;

public class JasperScanReport implements JRDataSource {
	private List<Scan> scanList = new ArrayList<Scan>();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<String, Object>();
	private Map<Integer, Integer> oldVulnsByChannelMap = new HashMap<Integer, Integer>();
			
	public JasperScanReport(List<Integer> applicationIdList, ScanDao scanDao) {
		if (scanDao != null && applicationIdList != null)
			this.scanList = scanDao.retrieveByApplicationIdList(applicationIdList);

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
		resultsHash.put("fixedVulns", scan.getNumberClosedVulnerabilities());
		resultsHash.put("resurfacedVulns", scan.getNumberResurfacedVulnerabilities());

		if (scan.getApplication() != null && scan.getApplication().getName() != null)
			resultsHash.put("name", scan.getApplication().getName());
		
		if (scan.getImportTime() != null)
			resultsHash.put("importTime", scan.getImportTime());
		
		Integer appChannelId = null;
		if (scan.getApplicationChannel() != null && scan.getApplicationChannel().getId() != null) {
			appChannelId = scan.getApplicationChannel().getId();
			oldVulnsByChannelMap.put(appChannelId, scan.getNumberTotalVulnerabilities());
		}
		
		// TODO Take a look at cleaning this up after we decide on the format for this report
		Integer numOld = scan.getNumberOldVulnerabilities();
		Integer numTotal = scan.getNumberTotalVulnerabilities();
		
		// This code counts in the old vulns from other channels.
		if (numTotal == null) numTotal = 0;
		if (numOld == null) numOld = 0;
		for (Integer key : oldVulnsByChannelMap.keySet()) {
			if (key == null || oldVulnsByChannelMap.get(key) == null || 
					(appChannelId != null && appChannelId.equals(key)))
				continue;
			numTotal += oldVulnsByChannelMap.get(key);
			numOld += oldVulnsByChannelMap.get(key);
		}
		
		resultsHash.put("oldVulns", numOld - scan.getNumberResurfacedVulnerabilities());
		resultsHash.put("totVulns", numTotal);
	}

}
