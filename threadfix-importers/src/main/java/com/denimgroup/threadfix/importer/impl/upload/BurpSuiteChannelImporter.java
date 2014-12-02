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
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 * @author mcollins
 *
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.BURPSUITE_DB_NAME,
        startingXMLTags = { "issues", "issue", "serialNumber", "type", "name", "host", "path" }
)
public class BurpSuiteChannelImporter extends AbstractChannelImporter {

	private static final String TEMPLATE_NAME = "name of an arbitrarily supplied request";
	private static final String REST_URL_PARAM = "REST URL parameter";
	private static final String MANUAL_INSERTION_POINT = "manual insertion point";
	private static final HashMap<String, String> SEVERITY_MAP = new HashMap<>();
	private static Pattern pattern = Pattern.compile("The payload <b>(.*)</b> was submitted");

    // We don't know why this happens but sometimes these strings show up in the burp XML.
	static {
		SEVERITY_MAP.put("deformation", "Information");
		SEVERITY_MAP.put("eddium", "Medium");
		SEVERITY_MAP.put(" igh", "High");
		SEVERITY_MAP.put("inw", "Low");
	}

	public BurpSuiteChannelImporter() {
		super(ScannerType.BURPSUITE);
		
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
		private boolean getParamValueText	  = false;
		private boolean getRequestText		  = false;
		private boolean getResponseText       = false;
		private boolean getScannerDetail      = false;
		private boolean getScannerRecommendation = false;
		private boolean getRawFinding		  = false;
		private boolean isBase64Encoded		  = false;
		 		
		private String currentScannerDetail   = null;
		private String currentScannerRecommendation = null;
		private StringBuffer currentRawFinding	  = new StringBuffer();
		private String currentParameterValue  = null;
		private String currentRequest         = null;
		private String currentResponse        = null;
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
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("location".equals(qName)) {
	    		getUrlText = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("serialNumber".equals(qName)) {
	    		getSerialNumber = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("host".equals(qName)) {
	    		getHostText = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("severity".equals(qName)) {
	    		getSeverityText = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("issues".equals(qName)) {
	    		date = DateUtils.getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy", atts.getValue("exportTime"));
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("request".equals(qName)) {
	    		getBackupParameter = true;
	    		getRequestText = true;
	    		isBase64Encoded = "true".equals(atts.getValue("base64"));
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("response".equals(qName)) {
	    		getResponseText = true;
	    		isBase64Encoded = "true".equals(atts.getValue("base64"));
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("issueDetail".equals(qName)) {
	    		getParamValueText = true;
	    		getScannerDetail = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("remediationDetail".equals(qName)) {
	    		getScannerRecommendation = true;
	    		getBuilderText(); //resets the stringbuffer
	    	} else if ("issue".equals(qName)){
	    		getRawFinding = true;
	    		getBuilderText(); //resets the stringbuffer
	    	}
	    	if (getRawFinding){
	    		currentRawFinding.append(makeTag(name, qName , atts));
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
		    		currentParameter = RegexUtils.getRegexResult(currentUrlText, "\\[(.*) parameter\\]");
		    		currentUrlText = RegexUtils.getRegexResult(currentUrlText, "^([^\\[]+)");
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
	    	} else if (getParamValueText) {
    		    currentParameterValue = getBuilderText();
    		    currentScannerDetail = currentParameterValue;
    		    Matcher m = pattern.matcher(currentParameterValue);
	    		if (m.find()){
	    			currentParameterValue = m.group(1);
	    		} else {
	    			currentParameterValue = "";
	    		}
	    		getParamValueText = false;
	    	} else if (getRequestText) {
	    		currentRequest = getBuilderText();
	    		if (currentRequest != null)
	    			try {
	    				if (isBase64Encoded) 
	    					currentRequest = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(currentRequest));
	    			}catch(Exception ignored){
	    				//sometimes the content throws an exception when decoding.  If so, just leave as-is
	    			}
	    		getRequestText = false;
	    	} else if (getResponseText) {
	    		currentResponse = getBuilderText();
	    		if (currentResponse != null)
	    			try{
	    				if (isBase64Encoded) 
	    					currentResponse = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(currentResponse));
	    			}catch(Exception ignored){
	    				//sometimes the content throws an exception when decoding.  If so, just leave as-is
	    			}
	    		getResponseText = false;
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
	    			currentBackupParameter = RegexUtils.getRegexResult(tempURL, "\\?(.*?)=");
	    		}
	    		
	    		getBackupParameter = false;
	    	} else if (getScannerRecommendation){
	    		currentScannerRecommendation = getBuilderText();
	    		getScannerRecommendation = false;
	    	}
	    	//if we're inside an <issue/>
	    	if (getRawFinding){
                currentRawFinding.append("</").append(qName).append(">\n");
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
	    		
	    		if (currentSeverityCode != null && SEVERITY_MAP.containsKey(currentSeverityCode.toLowerCase()) && SEVERITY_MAP.get(currentSeverityCode.toLowerCase()) != null) {
	    			currentSeverityCode = SEVERITY_MAP.get(currentSeverityCode.toLowerCase());
	    		}

                Map<FindingKey, String> findingMap = new HashMap<>();
                findingMap.put(FindingKey.PATH, currentHostText + currentUrlText);
                findingMap.put(FindingKey.PARAMETER, currentParameter);
                findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
                findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
                findingMap.put(FindingKey.CWE, null);
                findingMap.put(FindingKey.VALUE, currentParameterValue);
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
	    		currentSerialNumber    = null;
	    		currentBackupParameter = null;
	    		currentParameterValue  = null;
	    		currentRequest         = null;
	    		currentResponse        = null;
	    		currentScannerDetail   = null;
	    		currentScannerRecommendation = null;
	    		
	    		getRawFinding = false;
	    		currentRawFinding.setLength(0);
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (getChannelVulnText || getHostText || getUrlText || getParamText || 
	    			getSeverityText || getBackupParameter || getSerialNumber ||
	    			getParamValueText || getRequestText || getResponseText || 
	    			getScannerDetail || getScannerRecommendation ) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    	if (getRawFinding){
	    		currentRawFinding.append(ch, start, length);
	    	}
	    }
	}

	@Nonnull
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
	    		testDate = DateUtils.getCalendarFromString("EEE MMM dd kk:mm:ss zzz yyyy",
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
