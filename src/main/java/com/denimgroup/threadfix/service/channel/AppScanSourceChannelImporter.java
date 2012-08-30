////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.channel;

import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
public class AppScanSourceChannelImporter extends AbstractChannelImporter {

	@Autowired
	public AppScanSourceChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.APPSCAN_SOURCE);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new AppScanSourceSAXParser());
	}
	
	private Calendar getCalendarFromTimeInMillisString(String timeInMillis) {
		try {
			Long timeLong = Long.valueOf(timeInMillis);
			Calendar calendar = Calendar.getInstance();
			calendar.setTimeInMillis(timeLong);
			return calendar;
		} catch (NumberFormatException e) {
			log.warn("Invalid date timestamp in Appscan source file.", e);
			return null;
		}
	}

	public class AppScanSourceSAXParser extends DefaultHandler {

		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
				
		private int lineNumber = -1;
		
		private Map<String, String> vulnIdMap = new HashMap<String,String>();
					    
		private void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(true);
	    		saxFindingList.add(finding);
    		}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("Finding".equals(qName) && atts.getValue("vuln_type_id") != null) {
	    		currentChannelVulnCode = vulnIdMap.get(atts.getValue("vuln_type_id"));
	    		currentSeverityCode = atts.getValue("severity");
	    		try {
	    			lineNumber = Integer.parseInt(atts.getValue("line_number"));
	    		} catch (NumberFormatException e) {
	    			log.warn("AppScan Source importer found a non-integer " +
	    					"value in the line number attribute. Continuing.", e);
	    		}
	    		
	    		Finding finding = constructFinding(currentPath, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		finding.setSourceFileLocation(currentPath);
	    		DataFlowElement element = new DataFlowElement(currentPath, lineNumber, null);
	    		finding.setDataFlowElements(Arrays.asList(new DataFlowElement[] {element}));
	    		add(finding);
	    	} else if ("AssessmentFile".equals(qName)) {
	    		currentPath = atts.getValue("filename");
	    	} else if ("AssessmentStats".equals(qName)) {
	    		date = getCalendarFromTimeInMillisString(atts.getValue("date"));
	    	} else if ("StringIndex".equals(qName) && atts.getValue("id") != null && 
	    			atts.getValue("value") != null && 
	    			atts.getValue("value").startsWith("Vulnerability.")) {
	    		vulnIdMap.put(atts.getValue("id"), atts.getValue("value"));
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AppScanSourceSAXValidator());
	}
	
	public class AppScanSourceSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((testStatus == null || SUCCESSFUL_SCAN.equals(testStatus)) && !hasFindings)
	    		testStatus = EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("Finding".equals(qName) && atts.getValue("vuln_type_id") != null) {
	    		hasFindings = true;
	    	} else if ("AssessmentFile".equals(qName)) {
	    		correctFormat = true;
	    	} else if ("AssessmentStats".equals(qName)) {
	    		testDate = getCalendarFromTimeInMillisString(atts.getValue("date"));
	    		hasDate = testDate != null;
	    	}
	    }
	}
}
