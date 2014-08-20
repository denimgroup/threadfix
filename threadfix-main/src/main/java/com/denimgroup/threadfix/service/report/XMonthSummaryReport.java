////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service.report;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.Scan;

import java.text.DateFormatSymbols;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

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
public class XMonthSummaryReport {
	private List<List<Scan>> normalizedScans = new ArrayList<>();
	private List<String> dateList = new ArrayList<>();
	private int numMonths = 0;

	private ScanDao scanDao = null;

    private Integer teamId, appId;
    private String teamName, appName;

	
	private static final String[] months = new DateFormatSymbols().getMonths();
	
	public XMonthSummaryReport(List<List<Scan>> scanLists, ScanDao scanDao, int numMonths, ReportParameters parameters) {
		this.scanDao = scanDao;
		
		if (numMonths > 0 && numMonths <= 12) {
			this.numMonths = numMonths;
		} else {
			numMonths = 6;
		}
		
		if (scanLists != null && scanLists.size() > 0) {

            if (parameters.getOrganizationId() != -1 || parameters.getApplicationId() != -1) {
                Scan scan = null;
                for (List<Scan> scanList : scanLists) {
                    if (scanList != null && scanList.size() > 0) {
                        scan = scanList.get(0);
                        break;
                    }
                }
                if (scan != null) {
                    if (parameters.getApplicationId() != -1) {
                        Application application = scan.getApplication();
                        appId = application.getId();
                        appName = application.getName();
                        teamId = application.getOrganization().getId();
                        teamName = application.getOrganization().getName();
                    } else {
                        Organization organization = scan.getApplication().getOrganization();
                        teamId = organization.getId();
                        teamName = organization.getName();
                    }
                }
            }

			for (List<Scan> scanList : scanLists) {
				Collections.sort(scanList, Scan.getTimeComparator());
				normalizedScans.add(buildNormalizedScans(scanList));
			}
		}
	}

	/////////////////////////////////////////////////////////////
	//   These methods calculate the correct scan statistics   //
	/////////////////////////////////////////////////////////////
	
	private List<Scan> buildNormalizedScans(List<Scan> startingScans) {

		Map<Integer, Map<YearAndMonth, Scan>> channelScanMap = new HashMap<>();
		
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
		Map<YearAndMonth, Calendar> timeMap = new HashMap<>();
		
		Map<YearAndMonth, List<Integer>> scanIds = new HashMap<>();
		
		for (YearAndMonth time : times) {
			scanIds.put(time, new ArrayList<Integer>());
			if (scansHash != null) {
				for (Integer key : scansHash.keySet()) {
					if (scansHash.get(key) != null && scansHash.get(key).get(time) != null) {
						Scan scan = scansHash.get(key).get(time);
					
						scanIds.get(time).add(scan.getId());
						if (!timeMap.containsKey(time)) {
							timeMap.put(time, scan.getImportTime());
						}
					}
				}
			}
		}
		
		return scanIds;
	}
	
	private List<Scan> getFinalScans(Map<YearAndMonth, List<Integer>> results) {
		List<Scan> scanList = new ArrayList<>();
		
		for (YearAndMonth yearAndMonth : new TreeSet<>(results.keySet())) {
			
			List<Integer> result = results.get(yearAndMonth);
			if (result != null && !result.isEmpty()) {
				Map<String, Object> map = scanDao.getCountsForScans(result);
				
				Scan scan = new Scan();
				scan.setNumberCriticalVulnerabilities((Long) map.get("critical"));
				scan.setNumberHighVulnerabilities((Long) map.get("high"));
				scan.setNumberMediumVulnerabilities((Long) map.get("medium"));
				scan.setNumberLowVulnerabilities((Long) map.get("low"));
				scan.setNumberInfoVulnerabilities((Long) map.get("info"));
				
				dateList.add(yearAndMonth.getMonthName());
				
				scanList.add(scan);
			} else {
				Scan scan = new Scan();
				scan.setNumberCriticalVulnerabilities(0L);
				scan.setNumberHighVulnerabilities(0L);
				scan.setNumberMediumVulnerabilities(0L);
				scan.setNumberLowVulnerabilities(0L);
				scan.setNumberInfoVulnerabilities(0L);
				dateList.add(yearAndMonth.getMonthName());
				
				scanList.add(scan);
			}
			
			
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
		
		@Override
		public String toString() {
			return "" + year + "-" + month;
		}
		
		public YearAndMonth addMonths(int num) {
			if (num == 0) { return this; }
			
			if (month + num > 12) {
				return new YearAndMonth(year + (month + num) / 12, (month + num) % 12);
			} else if (month + num < 1) {
				return new YearAndMonth(year - 1 - (month + num) / 12, (month + num) % 12 + 12);
			} else {
				return new YearAndMonth(year, month + num);
			}
		}
		
		public List<YearAndMonth> pastXMonths(int numMonths) {
			YearAndMonth array[] = new YearAndMonth[numMonths];
			
			for (int i = 0; i < numMonths; i ++) {
				array[i] = this.addMonths(- i);
			}
			
			return list(array);
		}
		
		public String getMonthName() {
			return months[month-1];
		}
		
		@Override
		public int compareTo(YearAndMonth o) {
			
			int retVal;
			
			YearAndMonth other = o;
			if (other.year > this.year) {
				retVal = -1;
			} else if (this.year > other.year) {
				retVal = 1;
			} else if (other.month > this.month)  {
				retVal = -1;
			} else if (this.month > other.month) {
				retVal = 1;
			} else {
				retVal = 0;
			}
			
			return retVal;
		}
		
		@Override
		public boolean equals(Object o) {
			if (o != null && o instanceof YearAndMonth) {
				YearAndMonth object = (YearAndMonth) o;
				return object.year == this.year && object.month == this.month;
			} else {
				return false;
			}
		}
		
		@Override
		public int hashCode() {
			return year * 100 + month;
		}
	}
	
	private Map<String, Object> buildHash(int index) {
        Map<String, Object> hash = new HashMap<>();

		long numCritical = 0, numHigh = 0, numMedium = 0, numLow = 0, numInfo = 0;
		for (List<Scan> scanList: normalizedScans) {
			
			Scan scan = scanList.get(index);
			numCritical += scan.getNumberCriticalVulnerabilities();
			numHigh     += scan.getNumberHighVulnerabilities();
			numMedium   += scan.getNumberMediumVulnerabilities();
			numLow      += scan.getNumberLowVulnerabilities();
			numInfo     += scan.getNumberInfoVulnerabilities();
		}
		
        hash.put("Critical", numCritical);
        hash.put("High", numHigh);
        hash.put("Medium", numMedium);
        hash.put("Low", numLow);
        hash.put("Info", numInfo);

        hash.put("appId", appId);
        hash.put("appName", appName);
        hash.put("teamId", teamId);
        hash.put("teamName", teamName);

		if (dateList.get(index) != null) {
            hash.put("title", dateList.get(index));
            hash.put("time", dateList.get(index));
		}

        return hash;
	}

    public List<Map<String, Object>> buildReportList() {
        List<Map<String, Object>> resultList = null;
        if (normalizedScans != null && normalizedScans.size() > 0) {
            resultList = new ArrayList<>();
            for (int i=0; i< normalizedScans.get(0).size(); i++) {
                resultList.add(buildHash(i));
            }

        }
        return resultList;
    }
}
