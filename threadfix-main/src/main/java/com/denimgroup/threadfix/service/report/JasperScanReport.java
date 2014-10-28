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
import com.denimgroup.threadfix.data.entities.FilterJsonBlob;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.defects.utils.JsonUtils;
import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * This class provides the data source for the Trending Report.
 * @author mcollins
 *
 */
public class JasperScanReport implements JRDataSource {
	private List<Scan> scanList = list();
	private int index = 0;
	private Map<String, Object> resultsHash = new HashMap<>();
	private Map<Integer, Integer> totalVulnsByChannelMap = new HashMap<>();
    private Map<Integer, Long> infoVulnsByChannelMap = new HashMap<>();
    private Map<Integer, Long> lowVulnsByChannelMap = new HashMap<>();
    private Map<Integer, Long> mediumVulnsByChannelMap = new HashMap<>();
    private Map<Integer, Long> highVulnsByChannelMap = new HashMap<>();
    private Map<Integer, Long> criticalVulnsByChannelMap = new HashMap<>();
    private FilterJsonBlob filterJsonBlob;
    private Long startDate, endDate;
    private Integer startIndex, endIndex;
	
	public JasperScanReport(List<Integer> applicationIdList, ScanDao scanDao, FilterJsonBlob filterJsonBlob) {
        this.filterJsonBlob = filterJsonBlob;
		if (scanDao != null && applicationIdList != null)
			this.scanList = scanDao.retrieveByApplicationIdList(applicationIdList);
				
		Collections.sort(this.scanList, Scan.getTimeComparator());

        filterScanByTime();

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
			buildHash(index);
			return true;
		}
		else
			return false;
	}
	
	private Map<String, Object> buildHash(int index) {
        Map<String, Object> hash = newMap();
		Scan scan = scanList.get(index);
		
		if (scan == null) {
			return hash;
		}

        if (scan.getImportTime() != null) {
            resultsHash.put("importTime", scan.getImportTime());
            hash.put("importTime", scan.getImportTime());
        }

        if (filterJsonBlob == null) {
            resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
            resultsHash.put("resurfacedVulns", scan.getNumberResurfacedVulnerabilities());
            hash.put("New", scan.getNumberNewVulnerabilities());
            hash.put("Resurfaced", scan.getNumberResurfacedVulnerabilities());

            // Take out from the count old vulns from other channels.
            Integer adjustedTotal = scan.getNumberTotalVulnerabilities() -
                    scan.getNumberOldVulnerabilities() +
                    scan.getNumberOldVulnerabilitiesInitiallyFromThisChannel();

            Integer numTotal = trendingTotal(totalVulnsByChannelMap, scan, adjustedTotal);
            resultsHash.put("totVulns", numTotal);
            hash.put("Total", numTotal);
        } else {
            addFieldsDisplay(hash, scan);
        }
        return hash;
	}

    private void addFieldsDisplay(Map<String, Object> hash, Scan scan) {
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showNew"))) {
            hash.put("New", scan.getNumberNewVulnerabilities());
        }
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showResurfaced"))) {
            hash.put("Resurfaced", scan.getNumberResurfacedVulnerabilities());
        }
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showTotal"))) {
            Integer adjustedTotal = scan.getNumberTotalVulnerabilities() -
                    scan.getNumberOldVulnerabilities() +
                    scan.getNumberOldVulnerabilitiesInitiallyFromThisChannel();

            Integer numTotal = trendingTotal(totalVulnsByChannelMap, scan, adjustedTotal);
            hash.put("Total", numTotal);
        }
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showClosed"))) {
            hash.put("Closed", scan.getNumberClosedVulnerabilities());
        }
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showOld"))) {
            hash.put("Old", scan.getNumberOldVulnerabilities());
        }
        if ("true".equals(JsonUtils.getStringProperty(filterJsonBlob.getJson(), "showHidden"))) {
            hash.put("Hidden", scan.getNumberHiddenVulnerabilities());
        }

        String severitiesJson = JsonUtils.getStringProperty(filterJsonBlob.getJson(), "severities");
        if (severitiesJson != null) {
            if (severitiesJson.contains("info"))
                if ("true".equals(JsonUtils.getStringProperty(severitiesJson, "info"))) {
                    hash.put("Info", trendingAggr(infoVulnsByChannelMap, scan, scan.getNumberInfoVulnerabilities()));
                }
            if (severitiesJson.contains("low"))
                if ("true".equals(JsonUtils.getStringProperty(severitiesJson, "low"))) {
                    hash.put("Low", trendingAggr(lowVulnsByChannelMap, scan, scan.getNumberLowVulnerabilities()));
                }
            if (severitiesJson.contains("medium"))
                if ("true".equals(JsonUtils.getStringProperty(severitiesJson, "medium"))) {
                    hash.put("Medium", trendingAggr(mediumVulnsByChannelMap, scan, scan.getNumberMediumVulnerabilities()));
                }
            if (severitiesJson.contains("high"))
                if ("true".equals(JsonUtils.getStringProperty(severitiesJson, "high"))) {
                    hash.put("High", trendingAggr(highVulnsByChannelMap, scan, scan.getNumberHighVulnerabilities()));
                }
            if (severitiesJson.contains("critical"))
                if ("true".equals(JsonUtils.getStringProperty(severitiesJson, "critical"))) {
                    hash.put("Critical", trendingAggr(criticalVulnsByChannelMap, scan, scan.getNumberCriticalVulnerabilities()));
                }
        }
    }


    private Integer trendingTotal(Map<Integer, Integer> map, Scan scan, Integer newNum) {
        Integer appChannelId = null;
        if (scan.getApplicationChannel() != null && scan.getApplicationChannel().getId() != null) {
            appChannelId = scan.getApplicationChannel().getId();

            map.put(appChannelId, newNum);
        }

        Integer numTotal = newNum;

        // This code counts in the old vulns from other channels.
        for (Integer key : map.keySet()) {
            if (key == null || map.get(key) == null ||
                    (appChannelId != null && appChannelId.equals(key)))
                continue;
            numTotal += map.get(key);
        }
        return numTotal;
    }

    private Long trendingAggr(Map<Integer, Long> map, Scan scan, Long newNum) {
        Integer appChannelId = null;
        if (scan.getApplicationChannel() != null && scan.getApplicationChannel().getId() != null) {
            appChannelId = scan.getApplicationChannel().getId();

            map.put(appChannelId, newNum);
        }

        Long numTotal = newNum;

        // This code counts in the old vulns from other channels.
        for (Integer key : map.keySet()) {
            if (key == null || map.get(key) == null ||
                    (appChannelId != null && appChannelId.equals(key)))
                continue;
            numTotal += map.get(key);
        }
        return numTotal;
    }

    public List<Map<String, Object>> buildReportList() {
        List<Map<String, Object>> resultList = null;
        if (scanList != null && scanList.size() > 0) {
            resultList = new ArrayList<>();
            for (int i=0; i< scanList.size(); i++) {
                Map<String, Object> hash = buildHash(i);
                if ((startIndex == null || startIndex <= i)
                        && (endIndex == null || endIndex >= i))
                    resultList.add(hash);
            }
        }
        return resultList;
    }

    private void filterScanByTime(){
        int months = 0;
        Calendar date = Calendar.getInstance();
        if (filterJsonBlob == null) {
           // set default to a year trending report
            endDate = date.getTimeInMillis();
            startDate = (new GregorianCalendar(date.get(Calendar.YEAR), date.get(Calendar.MONTH) - 11, 1)).getTimeInMillis();
            filter();
            return;
        } else {
            String daysOld = "";
            if (filterJsonBlob.getJson().contains("daysOldModifier"))
                daysOld = JsonUtils.getStringProperty(filterJsonBlob.getJson(), "daysOldModifier");
            if ("LastYear".equals(daysOld)) {
                months = 11;
            } else if ("LastQuarter".equals(daysOld)) {
                months = 2;
            }
            if (months > 0) {
                endDate = date.getTimeInMillis();
                startDate = (new GregorianCalendar(date.get(Calendar.YEAR), date.get(Calendar.MONTH) - months, 1)).getTimeInMillis();
                filter();
                return;
            }

            if (filterJsonBlob.getJson().contains("startDate"))
                startDate = JsonUtils.getLongProperty(filterJsonBlob.getJson(), "startDate");
            if (filterJsonBlob.getJson().contains("endDate"))
                endDate = JsonUtils.getLongProperty(filterJsonBlob.getJson(), "endDate");
            filter();

        }
    }

    private void filter() {
        if (startDate == null) startIndex = 0;
        if (endDate == null) endIndex = this.scanList.size() - 1;
        for (int i = 0; i< this.scanList.size(); i++) {
            if (startIndex != null && endIndex != null)
                break;
            Scan scan = this.scanList.get(i);
            if (startIndex == null && startDate <= scan.getImportTime().getTimeInMillis()) {
                startIndex = i;
            }
            if (endIndex == null && endDate < scan.getImportTime().getTimeInMillis()) {
                endIndex = i - 1;
            }
        }
    }
}
