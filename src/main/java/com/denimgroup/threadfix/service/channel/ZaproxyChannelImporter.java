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

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * 
 * @author mcollins
 */
public class ZaproxyChannelImporter extends AbstractChannelImporter {

	@Autowired
	public ZaproxyChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.ZAPROXY);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new ZaproxySAXParser());
	}
	
	public class ZaproxySAXParser extends DefaultHandler {
		private Boolean getDate               = false;
		private Boolean getUri                = false;
		private Boolean getParameter          = false;
		private Boolean getChannelVulnName    = false;
		private Boolean getSeverityName       = false;
	
		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
					    
	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);
	    		saxFindingList.add(finding);
    		}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("report".equals(qName)) {
	    		getDate = true;
	    	} else if ("OWASPZAPReport".equals(qName)) {
	    		date = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", atts.getValue("generated"));
	    	} else if ("uri".equals(qName)) {
	    		getUri = true;
	    	} else if ("alert".equals(qName)) {
	    		getChannelVulnName = true;
	    	} else if ("param".equals(qName)) {
	    		getUri = false;
	    		getParameter = true;
	    	} else if ("riskcode".equals(qName)) {
	    		getSeverityName = true;
	    	} else if ("otherinfo".equals(qName)) {
	    		Finding finding = constructFinding(currentPath, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		add(finding);
	    	
	    		currentParameter       = null;
	    		currentPath            = null;
	    		getParameter           = false;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("report".equals(qName)) {
	    		getDate = false;
	    	} else if ("alert".equals(qName)) {
	    		getChannelVulnName = false;
	    	} else if ("alertitem".equals(qName)) {
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);

	    		String anchorString = "Report generated at ";
	    		if (tempDateString != null && !tempDateString.trim().isEmpty() && tempDateString.contains(anchorString)) {
	    			tempDateString = tempDateString.substring(tempDateString.indexOf(anchorString) + anchorString.length(),tempDateString.length()-2);
	    			date = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", tempDateString);
	    		}
	    		getDate = false;
	    	} else if (getUri) {
	    		currentPath = getText(ch,start,length);
	    		getUri = false;
	    	} else if (getChannelVulnName) {
	    		currentChannelVulnCode = getText(ch,start,length);
	    		getChannelVulnName = false;
	    	} else if (getParameter) {
	    		currentParameter = getText(ch,start,length);
	    		if (currentParameter != null && currentParameter.contains("="))
	    			currentParameter = currentParameter.substring(0,currentParameter.indexOf("="));
	    		getParameter = false;
	    	} else if (getSeverityName) {
	    		currentSeverityCode = getText(ch,start,length);
	    		getSeverityName = false;
	    	}
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new ZaproxySAXValidator());
	}
	
	public class ZaproxySAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
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
	    	if ("report".equals(qName)) {
	    		getDate = true;
	    		correctFormat = true;
	    	}
	    	
	    	if ("OWASPZAPReport".equals(qName)) {
	    		correctFormat = true;
	    		testDate = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", atts.getValue("generated"));
	    		if (testDate != null) {
    				hasDate = true;
    			}
	    	}
	    	
	    	if ("alertitem".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);
	    		
	    		String anchorString = "Report generated at ";
	    		if (tempDateString != null && !tempDateString.trim().isEmpty() && tempDateString.contains(anchorString)) {
	    			tempDateString = tempDateString.substring(tempDateString.indexOf(anchorString) + anchorString.length(),tempDateString.length()-2);
	    			testDate = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", tempDateString);
	    		
	    			if (testDate != null) {
	    				hasDate = true;
	    			}
	    		}
	    		
	    		getDate = false;
	    	}
	    }
	}
}
