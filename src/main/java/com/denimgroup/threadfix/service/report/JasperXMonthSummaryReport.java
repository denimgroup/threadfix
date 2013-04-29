package com.denimgroup.threadfix.service.report;

import java.text.DateFormatSymbols;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Scan;

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
public class JasperXMonthSummaryReport implements JRDataSource {
	private List<Scan> scanList, normalizedScans = new ArrayList<>();
	private List<String> dateList = new ArrayList<>();
	private int index = 0, numMonths = 0;
	private Map<String, Object> resultsHash = new HashMap<String, Object>();
	private Map<Integer, Map<YearAndMonth, Scan>> channelScanMap = new HashMap<>();
	private Map<YearAndMonth, Calendar> timeMap = new HashMap<>();
	
	private ScanDao scanDao = null;
	
	private static final String[] months = new DateFormatSymbols().getMonths();
	
	public JasperXMonthSummaryReport(List<Scan> scanList, ScanDao scanDao, int numMonths) {
		this.scanDao = scanDao;
		this.scanList = scanList;
		
		if (numMonths > 0 && numMonths <= 12) {
			this.numMonths = numMonths;
		} else {
			numMonths = 6;
		}
		
		if (this.scanList != null && this.scanList.size() > 0) {			
			Collections.sort(this.scanList, Scan.getTimeComparator());
			normalizedScans = buildNormalizedScans(this.scanList);
		}
		
		index = -1;
	}

	/////////////////////////////////////////////////////////////
	//   These methods calculate the correct scan statistics   //
	/////////////////////////////////////////////////////////////
	
	private List<Scan> buildNormalizedScans(List<Scan> startingScans) {

		for (Scan scan : startingScans) {
			YearAndMonth yearAndMonth = new YearAndMonth(scan.getImportTime());
			
			Integer applicationChannelId = scan.getApplicationChannel().getId();
			if (!channelScanMap.containsKey(applicationChannelId)) {
				channelScanMap.put(applicationChannelId, new HashMap<YearAndMonth, Scan>());
			}
			
			channelScanMap.get(applicationChannelId).put(yearAndMonth, scan);
		}
		
		YearAndMonth now = new YearAndMonth(Calendar.getInstance());

		addIntermediateScans(channelScanMap, now); 
		
		Map<YearAndMonth, List<Integer>> results = collapseScans(channelScanMap, now.pastXMonths(numMonths));
		
		return getFinalScans(results);
	}
	
	private void addIntermediateScans(Map<Integer, Map<YearAndMonth, Scan>>  scansHash, YearAndMonth now) {
		for (Integer key : scansHash.keySet()) {
			Map<YearAndMonth, Scan> entry = scansHash.get(key);
			TreeSet<YearAndMonth> times = new TreeSet<>(entry.keySet());
			YearAndMonth currentTime = times.first();
			Scan currentScan = entry.get(currentTime);
			while (currentTime.compareTo(now) <= 0) {
				
				if (entry.containsKey(currentTime)) {
					currentScan = entry.get(currentTime);
				} else {
					entry.put(currentTime, currentScan);
				}
				
				currentTime = currentTime.next();
			}
		}
	}
	
	private Map<YearAndMonth, List<Integer>> collapseScans(Map<Integer, Map<YearAndMonth, Scan>> scansHash, 
				List<YearAndMonth> times) {
		Map<YearAndMonth, List<Integer>> scanIds = new HashMap<>();
		
		for (YearAndMonth time : times) {
			scanIds.put(time, new ArrayList<Integer>());
			for (Integer key : scansHash.keySet()) {
				if (scansHash != null && scansHash.get(key) != null && scansHash.get(key).get(time) != null) {
					Scan scan = scansHash.get(key).get(time);
				
					scanIds.get(time).add(scan.getId());
					if (!timeMap.containsKey(time)) {
						timeMap.put(time, scan.getImportTime());
					}
				}
			}
		}
		
		return scanIds;
	}
	
	private List<Scan> getFinalScans(Map<YearAndMonth, List<Integer>> results) {
		List<Scan> scanList = new ArrayList<>();
		
		for (YearAndMonth yearAndMonth : new TreeSet<YearAndMonth>(results.keySet())) {
			
			Scan scan = new Scan();
			
			Map<String, Object> map = scanDao.getCountsForScans(results.get(yearAndMonth));
			
			scan.setNumberCriticalVulnerabilities((Long) map.get("critical"));
			scan.setNumberHighVulnerabilities((Long) map.get("high"));
			scan.setNumberMediumVulnerabilities((Long) map.get("medium"));
			scan.setNumberLowVulnerabilities((Long) map.get("low"));
			dateList.add(yearAndMonth.getMonthName());
			
			scanList.add(scan);
		}
		
		return scanList;
	}
	
	///////////////////////////////////////////////////////////////////
	//   This method makes it easier to use dates as keys in a map.  //
	///////////////////////////////////////////////////////////////////
	
	class YearAndMonth implements Comparable<YearAndMonth> {
		
		private int year, month;
		YearAndMonth(int year, int month) { this.year = year; this.month = month; }
		YearAndMonth(Calendar calendar) { 
			this.year = calendar.get(Calendar.YEAR);
			this.month = calendar.get(Calendar.MONTH) + 1;
		}
		public YearAndMonth next() {
			return addMonths(1);
		}
		
		public String toString() {
			return "" + year + "-" + month;
		}
		
		public YearAndMonth addMonths(int num) {
			if (num == 0) { return this; }
			
			if (month + num > 12) {
				return new YearAndMonth(year + ((month + num) / 12), ((month + num) % 12));
			} else if (month + num < 1) {
				return new YearAndMonth(year - 1 - ((month + num) / 12), ((month + num) % 12) + 12);
			} else {
				return new YearAndMonth(year, month + num);
			}
		}
		
		public List<YearAndMonth> pastXMonths(int numMonths) {
			YearAndMonth array[] = new YearAndMonth[numMonths];
			
			for (int i = 0; i < numMonths; i ++) {
				array[i] = this.addMonths(- i);
			}
			
			return Arrays.asList(array);
		}
		
		public String getMonthName() {
			return months[month-1];
		}
		
		@Override
		public int compareTo(YearAndMonth o) {
			if (o instanceof YearAndMonth) {
				YearAndMonth other = ((YearAndMonth) o);
				if (other.year > this.year) {
					return -1;
				} else if (this.year > other.year) {
					return 1;
				} else if (other.month > this.month)  {
					return -1;
				} else if (this.month > other.month){
					return 1;
				}
			}
			return 0;
		}
		
		public boolean equals(Object o) {
			if (o != null && o instanceof YearAndMonth) {
				YearAndMonth object = (YearAndMonth) o;
				return object.year == this.year && object.month == this.month;
			} else {
				return false;
			}
		}
		
		public int hashCode() {
			return year * 100 + month;
		}
	}
	
	////////////////////////////////////////////////////////////
	//   These methods implement the JRDataSource interface   //
	////////////////////////////////////////////////////////////
	
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
		if (normalizedScans != null && index < normalizedScans.size() - 1) {
			if (index == -1)
				index = 0;
			else
				index++;
			buildHash();
			return true;
		} else {
			return false;
		}
	}

	private void buildHash() {
		resultsHash.clear();

		Scan scan = normalizedScans.get(index);
		
		resultsHash.put("criticalVulns", scan.getNumberCriticalVulnerabilities());
		resultsHash.put("highVulns", scan.getNumberHighVulnerabilities());
		resultsHash.put("mediumVulns", scan.getNumberMediumVulnerabilities());
		resultsHash.put("lowVulns", scan.getNumberLowVulnerabilities());

		if (scan.getApplication() != null
				&& scan.getApplication().getName() != null)
			resultsHash.put("name", scan.getApplication().getName());

		if (dateList.get(index) != null)
			resultsHash.put("importTime", dateList.get(index));
	}
	
}
