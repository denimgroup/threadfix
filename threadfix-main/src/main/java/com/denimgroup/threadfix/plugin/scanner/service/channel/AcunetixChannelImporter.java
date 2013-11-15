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

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
@PluginImplementation
public class AcunetixChannelImporter extends AbstractChannelImporter {
	
	@Override
	public String getType() {
		return ScannerType.ACUNETIX_WVS.getFullName();
	}
	
	public AcunetixChannelImporter() {
		super(ScannerType.ACUNETIX_WVS.getFullName());
	}

	String detailsPattern = "input <b><font color=\"dark\">([^<]+)</font>";
	String pathPattern = "(.*) \\([a-z0-9]{25,50}\\)";

	@Override
	public Scan parseInput() {
		return parseSAXInput(new AcunetixSAXParser());
	}
	
	public class AcunetixSAXParser extends HandlerWithBuilder {
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
	    	switch (qName) {
		    	case "Name"      : getChannelVulnText = true; break;
		    	case "Affects"   : getUrlText = true;         break;
		    	case "Details"   : getParamText = true;       break;
		    	case "Severity"  : getSeverityText = true;    break;
		    	case "StartTime" : getDateText = true;        break;
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getBuilderText();
	    		getChannelVulnText = false;
	    	} else if (getUrlText) {
	    		currentUrlText = getBuilderText();
	    		if (currentUrlText != null && !currentUrlText.trim().equals("")) {
	    			String possibleString = getRegexResult(currentUrlText, pathPattern);
	    			if (possibleString != null) {
	    				currentUrlText = possibleString;
	    			}
	    		}
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		String text = getBuilderText();
	    		currentParameter = getRegexResult(text, detailsPattern);
	    		getParamText = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityText = false;
	    	} else if (getDateText) {
	    		String temp = getBuilderText();
	    		date = getCalendarFromString("dd/MM/yyyy, hh:mm:ss", temp);
	    		getDateText = false;
	    	}
	    	
	    	
	    	if ("ReportItem".equals(qName)) {
	    		
	    		if (currentChannelVulnCode.startsWith("GHDB")) {
	    			currentChannelVulnCode = "Google Hacking Database vulnerability found.";
	    		}
	    		
	    		if (currentChannelVulnCode.endsWith(" (verified)")) {
	    			currentChannelVulnCode = currentChannelVulnCode.replace(" (verified)", "");
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
	    	if (getChannelVulnText || getUrlText || getParamText || getSeverityText || getDateText) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AcunetixSAXValidator());
	}
	
	public class AcunetixSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDateText = false;
		
	    private void setTestStatus() {	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if (ScanImportStatus.SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings)
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
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDateText) {
	    		testDate = getCalendarFromString("dd/MM/yyyy, hh:mm:ss", getBuilderText());
	    		hasDate = testDate != null;
	    		getDateText = false;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length)
	    {
	    	if (getDateText) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}
}
