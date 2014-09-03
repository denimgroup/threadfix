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
import com.denimgroup.threadfix.data.entities.Scan;
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
					
		resultsHash.put("newVulns", scan.getNumberNewVulnerabilities());
		resultsHash.put("resurfacedVulns", scan.getNumberResurfacedVulnerabilities());
        hash.put("New", scan.getNumberNewVulnerabilities());
        hash.put("Resurfaced", scan.getNumberResurfacedVulnerabilities());
		
		if (scan.getImportTime() != null) {
            resultsHash.put("importTime", scan.getImportTime());
            hash.put("importTime", scan.getImportTime());
        }
		
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
        hash.put("Total", numTotal);

        return hash;
	}


    public List<Map<String, Object>> buildReportList() {
        List<Map<String, Object>> resultList = null;
        if (scanList != null && scanList.size() > 0) {
            resultList = new ArrayList<>();
            for (int i=0; i< scanList.size(); i++) {
                resultList.add(buildHash(i));
            }

        }
        return resultList;
    }
}
