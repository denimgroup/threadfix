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

import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import net.sf.jasperreports.engine.JRDataSource;
import net.sf.jasperreports.engine.JRField;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

/*
 * This is a class to replace / extend the SQL here that I couldn't figure out how to turn into HSQL very easily.
 * 
 * <![CDATA[SELECT
     (SELECT COUNT(*) FROM VULNERABILITY WHERE APPLICATIONID = 1) AS TOTAL_VULNERABILITY_COUNT,
     COUNT(*) AS FOUND_COUNT,
     100.00 * COUNT(*) / (SELECT COUNT(*) FROM VULNERABILITY WHERE APPLICATIONID = 1) AS FOUND_PERCENT,
     (SELECT COUNT(*) FROM VULNERABILITY WHERE APPLICATIONID = 1) - COUNT(*) AS MISSED_COUNT,
     100.00 * ((SELECT COUNT(*) FROM VULNERABILITY WHERE APPLICATIONID = 1) - COUNT(*)) / (SELECT COUNT(*) FROM VULNERABILITY WHERE APPLICATIONID = 1) AS MISSED_PERCENT,
     CHANNELTYPE.NAME AS CHANNELTYPE_NAME
FROM
     "PUBLIC"."APPLICATION" APPLICATION INNER JOIN "PUBLIC"."SCAN" SCAN ON APPLICATION."ID" = SCAN."APPLICATIONID"
     INNER JOIN "PUBLIC"."FINDING" FINDING ON SCAN."ID" = FINDING."SCANID"
     INNER JOIN "PUBLIC"."APPLICATIONCHANNEL" APPLICATIONCHANNEL ON SCAN."APPLICATIONCHANNELID" = APPLICATIONCHANNEL."ID"
     INNER JOIN "PUBLIC"."VULNERABILITY" VULNERABILITY ON FINDING."VULNERABILITYID" = VULNERABILITY."ID"
     INNER JOIN "PUBLIC"."CHANNELTYPE" CHANNELTYPE ON APPLICATIONCHANNEL."CHANNELTYPEID" = CHANNELTYPE."ID"
WHERE
        APPLICATION.ID = 1 and
        VULNERABILITY.ACTIVE = 1
GROUP BY
        CHANNELTYPE_NAME]]>
 * 
 * 
 */
public class JasperScannerComparisonReport implements JRDataSource {
	private List<Vulnerability> vulnerabilityList = list();
	private int index = 0, total = 0;
	
	private Map<String, Integer> scannerVulnCountMap = null;
	private Map<String, Integer> scannerFPCountMap = null;
	
	private List<String> scannerNames = null;
			
	public JasperScannerComparisonReport(List<Integer> applicationIdList, VulnerabilityDao vulnerabilityDao) {
		if (vulnerabilityDao != null && applicationIdList != null)
			this.vulnerabilityList = vulnerabilityDao.retrieveByApplicationIdList(applicationIdList);

		buildGenericVulnerabilityInformationArray();
		
		index = -1;
	}
	
	@Override
	public Object getFieldValue(JRField field) {
		if (field == null) return null;
		String name = field.getName();
		if (name == null) return null;
		
		if (name.equals("TOTAL_VULNERABILITY_COUNT")) {
			return total;
		} else if (name.equals("CHANNELTYPE_NAME")) {
			return scannerNames.get(index);
		} else if (name.equals("FOUND_COUNT")) {
			return scannerVulnCountMap.get(scannerNames.get(index));
		} else if (name.equals("FOUND_PERCENT")) {
			return 100.0 * scannerVulnCountMap.get(scannerNames.get(index)) / total;
		} else if (name.equals("MISSED_COUNT")) {
			return total - scannerVulnCountMap.get(scannerNames.get(index));
		} else if (name.equals("MISSED_PERCENT")) {
			return 100.0 * (total - scannerVulnCountMap.get(scannerNames.get(index))) / total;
		} else if (name.equals("FP_COUNT")) {
			return scannerFPCountMap.get(scannerNames.get(index));
		} else if (name.equals("FP_PERCENT")) {
			return 100.0 
					* scannerFPCountMap.get(scannerNames.get(index)) 
					/ scannerVulnCountMap.get(scannerNames.get(index));
		} else {
			return null;
		}
	}

	@Override
	public boolean next() {
		if (scannerVulnCountMap != null && index < scannerVulnCountMap.size() - 1) {
			index++;
			return true;
		} else {
			return false;
		}
	}
	
	private void buildGenericVulnerabilityInformationArray() {
		if (vulnerabilityList == null || vulnerabilityList.size() == 0)
			return;
		
		scannerFPCountMap = new HashMap<>();
		scannerVulnCountMap = new HashMap<>();
		
		Set<String> scannersInUse = new TreeSet<>();
		
		// For each vuln, go through its findings and add the scanner names to a set.
		// Then iterate through the set and increment each present scanner's vuln count.
		for (Vulnerability vuln : vulnerabilityList) {
			
			// we don't want to count invalid vulns
			//  if it's null or if it's inactive and not a false positive
			if (vuln == null || (!vuln.isActive() && !vuln.getHidden() && !vuln.getIsFalsePositive()))
				continue;
			
			scannersInUse.clear();
			
			if (!vuln.getIsFalsePositive())
				total++;
			
			// TODO think about a good way to do this without traversing so many objects
			for (Finding finding : vuln.getFindings()) {
				if (finding != null && finding.getChannelNameOrNull() != null) {
					scannersInUse.add(finding.getChannelNameOrNull());
				}
			}
			
			for (String scanner : scannersInUse) {
				if (!scannerVulnCountMap.containsKey(scanner)) {
					scannerVulnCountMap.put(scanner, 0);
					scannerFPCountMap.put(scanner, 0);
				}
				
				if (vuln.getIsFalsePositive()) {
					scannerFPCountMap.put(scanner, scannerFPCountMap.get(scanner) + 1);
				} else {
					scannerVulnCountMap.put(scanner, scannerVulnCountMap.get(scanner) + 1);
				}
			}
		}
		
		scannerNames = new ArrayList<>(scannerVulnCountMap.keySet());
		
		// Sort in descending order by number of vulns found.
		Collections.sort(scannerNames, new Comparator<String>() {
			public int compare(String o1, String o2) {
				if (o1 != null && o2 != null &&
						scannerVulnCountMap != null 
						&& scannerVulnCountMap.get(o1) != null
						&& scannerVulnCountMap.get(o2) != null) {
					return scannerVulnCountMap.get(o2).compareTo(scannerVulnCountMap.get(o1));
				} else {
					return 0;
				}
			}
		});
	}
}