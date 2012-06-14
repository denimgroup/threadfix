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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

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
 *
 */
public class BurpSuiteChannelImporter extends AbstractChannelImporter {
	
	private String TEMPLATE_NAME = "name of an arbitrarily supplied request";

	@Autowired
	public BurpSuiteChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.BURPSUITE);
		
		doSAXExceptionCheck = false;
	}

	@Override
	public Scan parseInput() {
		cleanInputStream();
		return parseSAXInput(new BurpSuiteSAXParser());
	}
	
	public void cleanInputStream() {
		if (inputStream == null)
			return;
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		
		String line = null, fullString = "";
		try {
			StringBuffer buffer = new StringBuffer();
			while ((line = reader.readLine()) != null) {
				while (line.contains("]]]"))
					line = line.replace("]]]", "] ]]");
				buffer.append(line);
			}
			fullString = buffer.toString();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		try {
			reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		inputStream = new ByteArrayInputStream(fullString.getBytes());
	}

	public class BurpSuiteSAXParser extends DefaultHandler {
		
		private boolean getChannelVulnText    = false;
		private boolean getUrlText            = false;
		private boolean getParamText          = false;
		private boolean getSeverityText       = false;
		private boolean getHostText           = false;
		private boolean getBackupParameter    = false;
		private boolean getSerialNumber       = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
		private String currentHostText        = null;
		private String currentBackupParameter = null;
		private String currentSerialNumber    = null;
	    
		private void add(Finding finding) {
			if (finding != null) {
				if (currentSerialNumber != null) {
					finding.setNativeId(currentSerialNumber);
				} else {
					finding.setNativeId(getNativeId(finding));
				}
				
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
	    	if ("name".equals(qName)) {
	    		getChannelVulnText = true;
	    	} else if ("location".equals(qName)) {
	    		getUrlText = true;
	    	} else if ("serialNumber".equals(qName)) {
	    		getSerialNumber = true;
	    	} else if ("host".equals(qName)) {
	    		getHostText = true;
	    	} else if ("severity".equals(qName)) {
	    		getSeverityText = true;
	    	} else if ("issues".equals(qName)) {
	    		date = getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy", 
	    				atts.getValue("exportTime"));
	    	} else if ("request".equals(qName)) {
	    		getBackupParameter = true;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("issue".equals(qName)) {
	    		
	    		// This is a temporary fix, we should take another look at why burp did this
	    		// before deciding on a final strategy
	    		if (currentParameter != null && currentParameter.equals(TEMPLATE_NAME)) {
	    			currentParameter = currentBackupParameter;
	    		}
	    		
	    		Finding finding = constructFinding(currentHostText + currentUrlText, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		
	    		add(finding);
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    		currentParameter       = null;
	    		currentUrlText         = null;
	    		currentSerialNumber    = null;
	    		currentBackupParameter = null;
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getText(ch, start, length);
	    		getChannelVulnText = false;
	    	} else if (getHostText) {
	    		currentHostText = getText(ch, start, length);
	    		getHostText = false;
	    	} else if (getUrlText) {
	    		currentUrlText = getText(ch, start, length);
	    		if (currentUrlText != null) {
		    		currentParameter = getRegexResult(currentUrlText, "\\[(.*) parameter\\]");
		    		currentUrlText = getRegexResult(currentUrlText, "^([^\\[]+)");
		    		if (currentUrlText != null)
		    			currentUrlText = currentUrlText.trim();
		    	}
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		currentParameter = getText(ch, start, length);
	    		getParamText = false;
	    	} else if (getSerialNumber) {
	    		currentSerialNumber = getText(ch, start, length);
	    		getSerialNumber = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getText(ch, start, length);
	    		getSeverityText = false;
	    	} else if (getBackupParameter) {
	    		String tempURL = getText(ch,start,length);
	    		if (tempURL != null && tempURL.contains("HTTP")) {
	    			tempURL = tempURL.substring(0, tempURL.indexOf("HTTP"));
	    		}
	    		
	    		if (tempURL != null && tempURL.contains("=") 
	    				&& tempURL.indexOf('=') == tempURL.lastIndexOf('=')) {
	    			currentBackupParameter = getRegexResult(tempURL, "\\?(.*?)=");
	    		}
	    		
	    		getBackupParameter = false;
	    	} 
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new BurpSuiteSAXValidator());
	}
	
	public class BurpSuiteSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
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

	    public void startElement (String uri, String name, String qName, Attributes atts) 
	    		throws SAXException {	    	
	    	if ("issues".equals(qName)) {
	    		testDate = getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy", 
	    				atts.getValue("exportTime"));
	    		if (testDate != null)
	    			hasDate = true;
	    		correctFormat = atts.getValue("burpVersion") != null;
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		hasFindings = true;	
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
