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
package com.denimgroup.threadfix.service.channel;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
public class ArachniChannelImporter extends AbstractChannelImporter {
	
	private static Map<String, String> tagMap = new HashMap<String, String>();
	static {
		tagMap.put("name", CHANNEL_VULN_KEY);
		tagMap.put("code", CHANNEL_SEVERITY_KEY);
		tagMap.put("variable", PARAMETER_KEY);
		tagMap.put("var", PARAMETER_KEY);
		tagMap.put("url", PATH_KEY);
	}
	
	// Since the severity mappings are static and not included in the XML output,
	// these have been reverse engineered from the code
	private static Map<String, String> severityMap = new HashMap<String, String>();
	static {
		severityMap.put("Allowed HTTP methods", "INFORMATIONAL");
		severityMap.put("A backdoor file exists on the server.", "HIGH");
		severityMap.put("A backup file exists on the server.", "HIGH");
		severityMap.put("Code injection", "HIGH");
		severityMap.put("Code injection (timing attack)", "HIGH");
		severityMap.put("A common directory exists on the server.", "MEDIUM");
		severityMap.put("A common sensitive file exists on the server.", "LOW");
		severityMap.put("Cross-Site Request Forgery", "HIGH");
		severityMap.put("Directory listing is enabled.", "LOW");
		severityMap.put("Misconfiguration in LIMIT directive of .htaccess file.", "HIGH");
		severityMap.put("HTTP PUT is enabled.", "HIGH");
		severityMap.put("Interesting server response.", "INFORMATIONAL");
		severityMap.put("LDAP Injection", "HIGH");
		severityMap.put("Operating system command injection", "HIGH");
		severityMap.put("Operating system command injection (timing attack)", "HIGH");
		severityMap.put("Path Traversal", "MEDIUM");
		severityMap.put("Response splitting", "MEDIUM");
		severityMap.put("Remote file inclusion", "HIGH");
		severityMap.put("SQL Injection", "HIGH");
		severityMap.put("Blind SQL Injection", "HIGH");
		severityMap.put("Blind SQL Injection (timing attack)", "HIGH");
		severityMap.put("Unencrypted password form.", "MEDIUM");
		severityMap.put("Unvalidated redirect", "MEDIUM");
		severityMap.put("WebDAV", "INFORMATIONAL");
		severityMap.put("XPath Injection", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS)", "HIGH");
		severityMap.put("Cross-Site Scripting in event tag of HTML element.", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS) in path", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML \"script\" tag.", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML tag.", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML &quot;script&quot; tag.", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS) in URI", "HIGH");
		severityMap.put("The TRACE HTTP method is enabled.", "MEDIUM");
		severityMap.put("Found a CAPTCHA protected form.", "INFORMATIONAL");
		severityMap.put("Credit card number disclosure.", "MEDIUM");
		severityMap.put("CVS/SVN user disclosure.", "LOW");
		severityMap.put("Disclosed e-mail address.", "INFORMATIONAL");
		severityMap.put("Found an HTML object.", "INFORMATIONAL");
		severityMap.put("Private IP address disclosure.", "LOW");
		severityMap.put("Disclosed US Social Security Number.", "HIGH");
	}

	@Autowired
	public ArachniChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.ARACHNI);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new ArachniSAXParser());
	}
	
	public class ArachniSAXParser extends HandlerWithBuilder {
		
		private boolean getDate   = false;
		private boolean inFinding = false;
		
		private String itemKey = null;
	
		private Map<String, String> findingMap = null;
					    
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
	    	if ("finish_datetime".equals(qName)) {
	    		getDate = true;
	    	} else if ("issue".equals(qName)) {
	    		findingMap = new HashMap<String, String>();
	    		inFinding = true;
	    	} else if (inFinding && tagMap.containsKey(qName)) {
	    		itemKey = tagMap.get(qName);
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("issue".equals(qName)) {
	    		// TODO instead look into why this error occurs
	    		
	    		if (findingMap.get(CHANNEL_VULN_KEY) != null && 
	    				findingMap.get(CHANNEL_VULN_KEY).equals("Cross-Site Scripting in HTML ")) {
	    			findingMap.put(CHANNEL_VULN_KEY, 
	    					"Cross-Site Scripting in HTML &quot;script&quot; tag.");
	    		}
	    		
	    		findingMap.put(CHANNEL_SEVERITY_KEY, severityMap.get(findingMap.get(CHANNEL_VULN_KEY)));

	    		Finding finding = constructFinding(findingMap);
	    		
	    		add(finding);
	    		findingMap = null;
	    		inFinding = false;
	    	} else if (inFinding && itemKey != null) {
	    		String currentItem = getBuilderText();
	    		
	    		if (currentItem != null && findingMap.get(itemKey) == null) {
	    			findingMap.put(itemKey, currentItem);
	    		}
	    		itemKey = null;
	    	} 
	    	
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);
	    		}
	    		getDate = false;
	    	} 
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || itemKey != null) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new ArachniSAXValidator());
	}
	
	public class ArachniSAXValidator extends HandlerWithBuilder {
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
	    	if ("arachni_report".equals(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if ("finish_datetime".equals(qName)) {
	    		getDate = true;
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			testDate = getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);
	    		}
	    		
	    		hasDate = testDate != null;
	    		getDate = false;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
}
