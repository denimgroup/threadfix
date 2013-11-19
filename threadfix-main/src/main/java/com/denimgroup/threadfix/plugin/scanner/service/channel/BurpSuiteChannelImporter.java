////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.plugin.scanner.service.channel;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 *
 */
@PluginImplementation
public class BurpSuiteChannelImporter extends AbstractChannelImporter {

	@Override
	public String getType() {
		return ScannerType.BURPSUITE.getFullName();
	}
	
	private static final String TEMPLATE_NAME = "name of an arbitrarily supplied request";
	private static final String REST_URL_PARAM = "REST URL parameter";
	private static final String MANUAL_INSERTION_POINT = "manual insertion point";
	private static final HashMap<String, String> SEVERITY_MAP = new HashMap<>();
	static {
		SEVERITY_MAP.put("deformation", "Information");
		SEVERITY_MAP.put("eddium", "Medium");
		SEVERITY_MAP.put(" igh", "High");
		SEVERITY_MAP.put("inw", "Low");
	}

	public BurpSuiteChannelImporter() {
		super(ScannerType.BURPSUITE.getFullName());
		
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
			log.warn("IOException while trying to clean input stream", e);
		}
		
		try {
			reader.close();
		} catch (IOException e) {
			log.warn("IOException while trying to close file input stream.", e);
		}
		
		inputStream = new ByteArrayInputStream(fullString.getBytes());
	}

	public class BurpSuiteSAXParser extends HandlerWithBuilder {
		
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
	    	if ("type".equals(qName)) {
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
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getBuilderText();
	    		getChannelVulnText = false;
	    	} else if (getHostText) {
	    		currentHostText = getBuilderText();
	    		getHostText = false;
	    	} else if (getUrlText) {
	    		currentUrlText = getBuilderText();
	    		if (currentUrlText != null) {
		    		currentParameter = getRegexResult(currentUrlText, "\\[(.*) parameter\\]");
		    		currentUrlText = getRegexResult(currentUrlText, "^([^\\[]+)");
		    		if (currentUrlText != null)
		    			currentUrlText = currentUrlText.trim();
		    	}
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		currentParameter = getBuilderText();
	    		getParamText = false;
	    	} else if (getSerialNumber) {
	    		currentSerialNumber = getBuilderText();
	    		getSerialNumber = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityText = false;
	    	} else if (getBackupParameter) {
	    		String tempURL = getBuilderText();
	    		if (tempURL != null && tempURL.contains("HTTP")) {
	    			tempURL = tempURL.substring(0, tempURL.indexOf("HTTP"));
	    		}
	    		
	    		if (tempURL != null && tempURL.contains("=") 
	    				&& tempURL.indexOf('=') == tempURL.lastIndexOf('=')) {
	    			currentBackupParameter = getRegexResult(tempURL, "\\?(.*?)=");
	    		}
	    		
	    		getBackupParameter = false;
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		
	    		// This is a temporary fix, we should take another look at why burp did this
	    		// before deciding on a final strategy
	    		if (currentParameter != null && currentParameter.equals(TEMPLATE_NAME)) {
	    			currentParameter = currentBackupParameter;
	    		}
	    		
	    		if (currentParameter != null && 
	    				(currentParameter.startsWith(REST_URL_PARAM) || 
	    				 currentParameter.startsWith(MANUAL_INSERTION_POINT))) {
	    			currentParameter = "";
	    		}
	    		
	    		if (SEVERITY_MAP.get(currentSeverityCode.toLowerCase()) != null) {
	    			currentSeverityCode = SEVERITY_MAP.get(currentSeverityCode.toLowerCase());
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
	    	if (getChannelVulnText || getHostText || getUrlText || getParamText || 
	    			getSeverityText || getBackupParameter || getSerialNumber) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new BurpSuiteSAXValidator());
	}
	
	public class BurpSuiteSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (ScanImportStatus.SUCCESSFUL_SCAN == testStatus && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
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
