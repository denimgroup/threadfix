package com.denimgroup.threadfix.service.report;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public class JasperCWEReport implements JRDataSource {
	private List<Vulnerability> vulnerabilityList = new ArrayList<>();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<>();
	
	private List<Map<String, Object>> listOfMaps = null;
			
	public JasperCWEReport(List<Integer> applicationIdList, VulnerabilityDao vulnerabilityDao) {
		if (vulnerabilityDao != null && applicationIdList != null) {
			this.vulnerabilityList = vulnerabilityDao.retrieveByApplicationIdList(applicationIdList);
		}

		listOfMaps = buildGenericVulnerabilityInformationArray();
		
		index = -1;
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
		
		if (resultsHash != null && resultsHash.containsKey(name)) {
			return resultsHash.get(name);
		} else {
			return null;
		}
	}

	@Override
	public boolean next() {
		if (listOfMaps != null && index < listOfMaps.size() - 1) {
			if (index == -1) {
				index = 0;
			} else {
				index++;
			}
			resultsHash = listOfMaps.get(index);
			
			return true;
		} else {
			return false;
		}
	}
	
	private List<Map<String, Object>> buildGenericVulnerabilityInformationArray() {
		if (vulnerabilityList == null || vulnerabilityList.size() == 0) {
			return null;
		}
		
		// First we need to marshal the data from vulnerabilities into groups by generic vulnerability
		Map<String, Map<String, Integer>> statsMap = new HashMap<>();
		
		Calendar now = Calendar.getInstance();
		
		for (Vulnerability vulnerability : vulnerabilityList) {
			if (vulnerability == null
					|| vulnerability.getGenericVulnerability() == null
					|| vulnerability.getGenericVulnerability().getName() == null
					|| vulnerability.getIsFalsePositive()
					|| vulnerability.getHidden()) {
				continue;
			}
			String key = vulnerability.getGenericVulnerability().getName();
			
			// initialize the generic vuln
			if (!statsMap.containsKey(key)) {
				statsMap.put(key, new HashMap<String, Integer>());
				statsMap.get(key).put("numOpen", 0);
				statsMap.get(key).put("numClosed", 0);
				statsMap.get(key).put("totalAgeOpen", 0);
				statsMap.get(key).put("totalTimeToClose", 0);
			}

			// bump up the correct stats
			if (vulnerability.isActive() && !vulnerability.getHidden()) {
				statsMap.get(key).put("numOpen", statsMap.get(key).get("numOpen")+1);
				statsMap.get(key).put("totalAgeOpen", statsMap.get(key).get("totalAgeOpen") + dateDiffInDays(vulnerability.getOpenTime(), now));
			} else {
				statsMap.get(key).put("numClosed", statsMap.get(key).get("numClosed")+1);
				statsMap.get(key).put("totalTimeToClose", statsMap.get(key).get("totalTimeToClose") + dateDiffInDays(vulnerability.getOpenTime(), vulnerability.getCloseTime()));
			}
		}
		
		// Then, to sort, we need a grouping of total vulns with all the associated vuln names
		Map<Integer, List<String>> sortingHash = new HashMap<>();
		
		for (String key : statsMap.keySet()) {
			Integer total = statsMap.get(key).get("numOpen") + statsMap.get(key).get("numClosed");
			
			if (sortingHash.get(total) == null) {
				sortingHash.put(total, new ArrayList<String>());
			}
			
			sortingHash.get(total).add(key);
		}
		
		List<Map<String, Object>> returnList = new ArrayList<>();
				
		// moving to a SortedSet allows ordered addition by total number of vulnerabilities.
		SortedSet<Integer> sortedSet = new TreeSet<>();
		sortedSet.addAll(sortingHash.keySet());
		
		// then iterate through the original set of generic vulnerability data
		// and calculate the correct figures.
		for (Integer sortingHashKey : sortedSet) {
			for (String statsMapKey : sortingHash.get(sortingHashKey)) {
				
				Map<String, Object> genericVulnEntry = new HashMap<>();
				genericVulnEntry.put("description", statsMapKey);
				genericVulnEntry.put("total", Long.valueOf(sortingHashKey));
				
				Map<String, Integer> statsMapEntry = statsMap.get(statsMapKey);
				
				if (sortingHashKey == 0) {
					genericVulnEntry.put("percentClosed", Long.valueOf(100));
				} else {
					Long percentClosed = (long) (100.0 * ((double)statsMapEntry.get("numClosed") / (double)sortingHashKey));
					genericVulnEntry.put("percentClosed", percentClosed);
				}
				
				if (statsMapEntry.get("numOpen") == 0) {
					genericVulnEntry.put("averageAgeOpen", Long.valueOf(0));
				} else {
					Long averageAgeOpen = (long) (statsMapEntry.get("totalAgeOpen") / statsMapEntry.get("numOpen"));
					genericVulnEntry.put("averageAgeOpen",averageAgeOpen);
				}
				
				if (statsMapEntry.get("numClosed") == 0) {
					genericVulnEntry.put("averageTimeToClose", Long.valueOf(0));
				} else {
					Long averageTimeToClose = (long) (statsMapEntry.get("totalTimeToClose") / statsMapEntry.get("numClosed"));
					genericVulnEntry.put("averageTimeToClose",averageTimeToClose);
				}
				
				// the 0 as the first argument bumps all the other items up one index.
				returnList.add(0,genericVulnEntry);
			}
		}
		return returnList;
	}

	private Integer dateDiffInDays(Calendar firstDate, Calendar secondDate) {
		if (firstDate == null || secondDate == null) {
			return 0;
		}
		Calendar earlierDate = null, laterDate = null;
		
		if (firstDate.compareTo(secondDate) == 0) {
			return 0;
		} else if (firstDate.compareTo(secondDate) < 0) {
			earlierDate = firstDate;
			laterDate = secondDate;
		} else {
			earlierDate = secondDate;
			laterDate = firstDate;
		}
		
		Integer days = 0;
		
		earlierDate.add(Calendar.DAY_OF_MONTH, 1);
		while (earlierDate.compareTo(laterDate) < 0) {
			days += 1;
			earlierDate.add(Calendar.DAY_OF_MONTH, 1);
		}
		return days;
	}
}
