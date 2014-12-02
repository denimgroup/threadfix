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

package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.data.entities.ScannerDatabaseNames.ACUNETIX_WVS_DB_NAME;

/**
 * 
 * @author mcollins
 */
@ScanImporter(
        scannerName = ACUNETIX_WVS_DB_NAME,
        startingXMLTags = {"ScanGroup", "Scan", "Name", "ShortName", "StartURL", "StartTime"}
)
public class AcunetixChannelImporter extends AbstractChannelImporter {
	
	public AcunetixChannelImporter() {
		super(ScannerType.ACUNETIX_WVS);
	}

	private static final String DETAILS_PATTERN = "input <b><font color=\"dark\">([^<]+)</font>",
            PATH_PATTERN = "(.*) \\([a-z0-9]{25,50}\\)";

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
        private boolean getRequestText		  = false;
        private boolean getResponseText       = false;
        private boolean getScannerDetail      = false;
        private boolean getScannerRecommendation = false;
        private boolean inFinding		  = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
        private String currentScannerDetail   = null;
        private String currentScannerRecommendation = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();
        private String currentRequest         = null;
        private String currentResponse        = null;

        Map<FindingKey, String> findingMap = new HashMap<>();
		
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
                case "Description" : getScannerDetail = true;        break;
                case "Recommendation" : getScannerRecommendation = true;        break;
                case "Request" : getRequestText = true;        break;
                case "Response" : getResponseText = true;        break;
                case "ReportItem" : inFinding = true;        break;
	    	}
            if (inFinding){
                currentRawFinding.append(makeTag(name, qName , atts));
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
	    			String possibleString = RegexUtils.getRegexResult(currentUrlText, PATH_PATTERN);
	    			if (possibleString != null) {
	    				currentUrlText = possibleString;
	    			}
	    		}
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		String text = getBuilderText();
	    		currentParameter = RegexUtils.getRegexResult(text, DETAILS_PATTERN);
	    		getParamText = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityText = false;
	    	} else if (getDateText) {
	    		String temp = getBuilderText();
	    		date = DateUtils.getCalendarFromString("dd/MM/yyyy, hh:mm:ss", temp);
	    		getDateText = false;
	    	} else if (getRequestText) {
                currentRequest = getBuilderText();
                getRequestText = false;
            } else if (getResponseText) {
                currentResponse = getBuilderText();
                getResponseText = false;
            } else if (getScannerDetail) {
                currentScannerDetail = getBuilderText();
                getScannerDetail = false;
            } else if (getScannerRecommendation) {
                currentScannerRecommendation = getBuilderText();
                getScannerRecommendation = false;
            }

            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }
	    	
	    	if ("ReportItem".equals(qName)) {
	    		
	    		if (currentChannelVulnCode.startsWith("GHDB")) {
	    			currentChannelVulnCode = "Google Hacking Database vulnerability found.";
	    		}
	    		
	    		if (currentChannelVulnCode.endsWith(" (verified)")) {
	    			currentChannelVulnCode = currentChannelVulnCode.replace(" (verified)", "");
	    		}

                findingMap.put(FindingKey.PATH, currentUrlText);
                findingMap.put(FindingKey.PARAMETER, currentParameter);
                findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
                findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
                findingMap.put(FindingKey.CWE, null);
                findingMap.put(FindingKey.VALUE, null);
                findingMap.put(FindingKey.REQUEST, currentRequest);
                findingMap.put(FindingKey.RESPONSE, currentResponse);
                findingMap.put(FindingKey.DETAIL, currentScannerDetail);
                findingMap.put(FindingKey.RECOMMENDATION, currentScannerRecommendation);
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

                Finding finding = constructFinding(findingMap);
	    		add(finding);
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    		currentParameter       = null;
	    		currentUrlText         = null;
                currentRequest         = null;
                currentResponse        = null;
                currentScannerDetail     = null;
                currentScannerRecommendation     = null;
                inFinding 			   = false;
                currentRawFinding.setLength(0);
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText || getUrlText
                    || getParamText || getSeverityText || getDateText
                    || getRequestText || getResponseText
                    || getScannerDetail || getScannerRecommendation) {
	    		addTextToBuilder(ch,start,length);
	    	}
            if (inFinding)
                currentRawFinding.append(ch,start,length);
	    }
	}

	@Nonnull
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
	    		testDate = DateUtils.getCalendarFromString("dd/MM/yyyy, hh:mm:ss", getBuilderText());
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
