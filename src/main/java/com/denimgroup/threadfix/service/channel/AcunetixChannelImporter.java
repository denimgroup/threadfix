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
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * 
 * @author mcollins
 */
public class AcunetixChannelImporter extends AbstractChannelImporter {
	
	String detailsPattern = "input <b><font color=\"dark\">([^<]+)</font>";

	@Autowired
	public AcunetixChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.ACUNETIX_WVS);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new AcunetixSAXParser());
	}
	
	public class AcunetixSAXParser extends DefaultHandler {
		private boolean getChannelVulnText    = false;
		private boolean getUrlText            = false;
		private boolean getParamText          = false;
		private boolean getSeverityText       = false;
		private boolean getDateText           = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
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
	    	if ("Name".equals(qName)) {
	    		getChannelVulnText = true;
	    	} else if ("Affects".equals(qName)) {
	    		getUrlText = true;
	    	} else if ("Details".equals(qName)) {
	    		getParamText = true;
	    	} else if ("Severity".equals(qName)) {
	    		getSeverityText = true;
	    	} else if ("StartTime".equals(qName)) {
	    		getDateText = true;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("ReportItem".equals(qName)) {
	    		
	    		if (currentChannelVulnCode.startsWith("GHDB")) {
	    			currentChannelVulnCode = "Google Hacking Database vulnerability found.";
	    		}
	    		
	    		Finding finding = constructFinding(currentUrlText, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		
	    		add(finding);
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    		currentParameter       = null;
	    		currentUrlText         = null;
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getText(ch, start, length);
	    		getChannelVulnText = false;
	    	} else if (getUrlText) {
	    		currentUrlText = getText(ch, start, length);
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		String text = getText(ch, start, length);
	    		currentParameter = getRegexResult(text,detailsPattern);
	    		getParamText = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getText(ch, start, length);
	    		getSeverityText = false;
	    	} else if (getDateText) {
	    		date = getCalendarFromString("dd/MM/yyyy, hh:mm:ss", getText(ch, start, length));
	    		getDateText = false;
	    	}
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new AcunetixSAXValidator());
	}
	
	public class AcunetixSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDateText = false;
		
	    private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings)
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
	    	if ("ScanGroup".equals(qName)) {
	    		correctFormat = true;
	    	} else if ("StartTime".equals(qName)) {
	    		getDateText = true;
	    	}
	    	
	    	if ("ReportItem".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length)
	    {
	    	if (getDateText) {
	    		testDate = getCalendarFromString("dd/MM/yyyy, hh:mm:ss", getText(ch, start, length));
	    		hasDate = testDate != null;
	    		getDateText = false;
	    	}
	    }
	}
}
