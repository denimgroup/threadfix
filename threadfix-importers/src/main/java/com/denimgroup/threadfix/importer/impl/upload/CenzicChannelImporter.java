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
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
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

/**
 * 
 * @author stran
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.CENZIC_HAILSTORM_DB_NAME,
        startingXMLTags = { "Assessments", "AssessmentRunData" }
)
public class CenzicChannelImporter extends AbstractChannelImporter {

    private static final String EXTERNAL_APPLET_SCRIPT_OBJECT = "External Applet, Script, or Object",
            DB_EXTERNAL_APPLET_SCRIPT_OBJECT = "External Applet Script or Object";

    private static final String PAYLOAD_PATTERN = "\\?(.*)",
            PATH_PATTERN = "(.*)\\?",
            CWE_PATTERN = "CWE-(.*)",
            PARAM_PATTERN = ":(.*)";


	public CenzicChannelImporter() {
		super(ScannerType.CENZIC_HAILSTORM);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new CenzicSAXParser());
	}
	
	public class CenzicSAXParser extends HandlerWithBuilder {

        Map<FindingKey, String> findingMap = new HashMap<>();

        private boolean getReportItemType = false;
        private boolean getChannelVulnText    = false;
		private boolean getUrlText            = false;
		private boolean getParamText          = false;
		private boolean getSeverityText       = false;
		private boolean getItemDateText = false;
        private boolean getDateText = false;
        private boolean getRequestText		  = false;
        private boolean getResponseText       = false;
        private boolean getScannerDetail      = false;
        private boolean getScannerRecommendation = false;
        private boolean inFinding		  = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
        private String currentReportItemType = null;
        private String currentCweId = null;
        private String currentScannerDetail   = null;
        private String currentScannerRecommendation = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();
        private String currentRequest         = null;
        private String currentResponse        = null;
		
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
                case "SmartAttackInfo" : currentCweId = atts.getValue("VulnerabilityIds"); break;
                case "StartTime"    : getDateText = true; break;
		    	case "SmartAttackName"      : getChannelVulnText = true; break;
		    	case "Url"   : getUrlText = true;         break;
		    	case "field"   : getParamText = true;       break;
		    	case "Severity"  : getSeverityText = true;    break;
		    	case "ReportItemCreateDate" : getItemDateText = true;        break;
                case "ReportItemType" : getReportItemType = true;        break;
                case "Remediation" : getScannerRecommendation = true;        break;
                case "Message" : getScannerDetail = true;        break;
                case "HttpRequest" : getRequestText = true;        break;
                case "HttpResponse" : getResponseText = true;        break;
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
                if (currentChannelVulnCode.equalsIgnoreCase(EXTERNAL_APPLET_SCRIPT_OBJECT))
                    currentChannelVulnCode = DB_EXTERNAL_APPLET_SCRIPT_OBJECT;
	    		getChannelVulnText = false;
	    	} else if (getUrlText) {
	    		currentUrlText = getBuilderText();
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		String text = getBuilderText();
                currentParameter = RegexUtils.getRegexResult(text, PARAM_PATTERN);
                if (currentParameter != null) {
                    currentParameter = currentParameter.trim();
                }
                getParamText = false;
            } else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityText = false;
	    	} else if (getItemDateText) {
                String temp = getBuilderText();
                if (date == null) {
                    date = DateUtils.getCalendarFromString("MM/dd/yyyy hh:mm:ss a", temp);
                }
	    		getItemDateText = false;
            } else if (getDateText) {
                String temp = getBuilderText();
                if (date == null) {
                    date = DateUtils.getCalendarFromString("MM/dd/yyyy hh:mm:ss", temp);
                }
                getDateText = false;
	    	} else if (getReportItemType) {
                currentReportItemType = getBuilderText();
                getReportItemType = false;
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

                if ("Vulnerable".equalsIgnoreCase(currentReportItemType)) {

                    String possibleUrl = RegexUtils.getRegexResult(currentUrlText, PATH_PATTERN);
                    String payload = RegexUtils.getRegexResult(currentUrlText, PAYLOAD_PATTERN);
                    currentUrlText = (possibleUrl==null)? currentUrlText : possibleUrl;

                    findingMap.put(FindingKey.PATH, currentUrlText);
                    findingMap.put(FindingKey.PARAMETER, currentParameter);
                    findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
                    findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
                    findingMap.put(FindingKey.CWE, RegexUtils.getRegexResult(currentCweId, CWE_PATTERN));
                    findingMap.put(FindingKey.VALUE, payload);
                    findingMap.put(FindingKey.REQUEST, currentRequest);
                    findingMap.put(FindingKey.RESPONSE, currentResponse);
                    findingMap.put(FindingKey.DETAIL, currentScannerDetail);
                    findingMap.put(FindingKey.RECOMMENDATION, currentScannerRecommendation);
                    findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

                    Finding finding = constructFinding(findingMap);
                    add(finding);

                    add(finding);
                }

	    		currentSeverityCode    = null;
	    		currentParameter       = null;
	    		currentUrlText         = null;
                currentReportItemType = null;
                currentRequest         = null;
                currentResponse        = null;
                currentScannerDetail     = null;
                inFinding 			   = false;
                currentRawFinding.setLength(0);
	    	}

            if ("SmartAttacksData".equals(qName)) {
                currentScannerRecommendation     = null;
                currentChannelVulnCode = null;
                currentCweId = null;
            }
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText || getUrlText || getParamText || getSeverityText || getItemDateText || getReportItemType || getDateText
                    || getRequestText || getResponseText || getScannerDetail || getScannerRecommendation) {
	    		addTextToBuilder(ch,start,length);
	    	}
            if (inFinding)
                currentRawFinding.append(ch,start,length);
	    }
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new CenzicSAXValidator());
	}
	
	public class CenzicSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDateText = false;
        private boolean getReportItemType = false;
		
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

	    public void startElement (String uri, String name, String qName, Attributes atts) {
	    	if ("Assessments".equals(qName)) {
	    		correctFormat = true;
	    	} else if ("ReportItemCreateDate".equals(qName)) {
	    		getDateText = true;
	    	}
	    	
            if ("ReportItemType".equals(qName)) {
                getReportItemType = true;
            }
	    }
	    
	    public void endElement(String uri, String name, String qName) throws SAXException {
	    	if (getDateText) {
	    		testDate = DateUtils.getCalendarFromString("MM/dd/yyyy hh:mm:ss a", getBuilderText());
	    		hasDate = testDate != null;
	    		getDateText = false;
	    	}
            if (getReportItemType && hasDate) {
                hasFindings = true;
                setTestStatus();
                throw new SAXException(FILE_CHECK_COMPLETED);
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
