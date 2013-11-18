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

import java.util.AbstractMap.SimpleEntry;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
@PluginImplementation
public class ZaproxyChannelImporter extends AbstractChannelImporter {

	private static final String SQL_INJECTION = "SQL Injection", XSS = "Cross Site Scripting";
	
	private static final Set<Entry<String[], String>> alternativesMap = new HashSet<>();
	private static void addToSet(String[] array, String key) {
		alternativesMap.add(new SimpleEntry<>(array,  key));
	}
	static {
		addToSet(new String[] {"sql", "injection"},  SQL_INJECTION);
		addToSet(new String[] {"sqli"},  SQL_INJECTION);
		addToSet(new String[] {"cross", "site", "scripting"},  XSS);
		addToSet(new String[] {"xss"},  XSS);
	}
	
	@Autowired
	public ZaproxyChannelImporter() {
		super(ScannerType.ZAPROXY.getFullName());
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new ZaproxySAXParser());
	}
	
	private String getAlternative(String possibility) {
		String lower = possibility.toLowerCase();
		MAP: for (Entry<String[], String> entry : alternativesMap) {
			for (String key : entry.getKey()) {
				if (!lower.contains(key)) {
					continue MAP;
				}
			}
			// if we get here then the string contains all the keys
			return entry.getValue();
		}
		return null;
	}
	
	public class ZaproxySAXParser extends HandlerWithBuilder {
		private Boolean getDate               = false;
		private Boolean getUri                = false;
		private Boolean getParameter          = false;
		private Boolean getChannelVulnName    = false;
		private Boolean getSeverityName       = false;
		private Boolean getCweId			  = false;
	
		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
		private String currentCweId			  = null;
		
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
	    
	    @Override
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
	    	} else if ("cweid".equals(qName)) {
	    		getCweId = true;
	    	}
	    }

	    @Override
		public void endElement (String uri, String name, String qName)
	    {
	    	if ("report".equals(qName)) {
	    		getDate = false;
	    	} else if ("alertitem".equals(qName)) {

	    		Finding finding = constructFinding(currentPath, currentParameter,
	    				currentChannelVulnCode, currentSeverityCode, currentCweId);
	    		if (finding != null && finding.getChannelVulnerability() == null) {
	    			
	    			String channelVulnerabilityCode = getAlternative(currentChannelVulnCode);
	    			if (channelVulnerabilityCode != null) {
		    			ChannelVulnerability channelVulnerability = getChannelVulnerability(channelVulnerabilityCode);
		    			finding.setChannelVulnerability(channelVulnerability);
	    			}
	    		}
	    		add(finding);
	    		currentParameter       = null;
	    		currentPath            = null;
	    		getParameter           = false;
	    		
	    		currentChannelVulnCode = null;
	    		currentSeverityCode    = null;
	    		currentCweId 		   = null;
	    		
	    	} else if (getUri) {
	    		currentPath = getBuilderText();
	    		getUri = false;
	    	} else if (getChannelVulnName) {
	    		currentChannelVulnCode = getBuilderText();
	    		getChannelVulnName = false;
	    	} else if (getParameter) {
	    		currentParameter = getBuilderText();
	    		
	    		if (currentParameter != null && currentParameter.contains("=")) {
					currentParameter = currentParameter.substring(0,currentParameter.indexOf("="));
				}
	    		getParameter = false;
	    	} else if ("riskcode".equals(qName)) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityName = false;
	    	} else if (getDate) {
	    		String tempDateString = getBuilderText();

	    		String anchorString = "Report generated at ";
	    		if (tempDateString != null && !tempDateString.trim().isEmpty() && tempDateString.contains(anchorString)) {
	    			tempDateString = tempDateString.substring(tempDateString.indexOf(anchorString) + anchorString.length(),tempDateString.length()-2);
	    			date = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", tempDateString);
	    		}
	    		getDate = false;
	    	} else if (getCweId) {
	    		currentCweId = getBuilderText();
	    		getCweId = false;
	    	}
	    }
	    
	    @Override
		public void characters (char ch[], int start, int length) {
	    	if (getDate || getParameter || getUri || getChannelVulnName || getSeverityName || getCweId) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new ZaproxySAXValidator());
	}
	
	public class ZaproxySAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat) {
				testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
			} else if (hasDate) {
				testStatus = checkTestDate();
			}
	    	if ((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings) {
				testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
			} else if (testStatus == null) {
				testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
			}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    @Override
		public void endDocument() {
	    	setTestStatus();
	    }

	    @Override
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	log.debug("Starting XML element with name:" + name + " and qName: " + qName);
	    	
	    	if (getDate) {
	    		//	TODO - Determine if there is overlap between this code and the handler for OWASPZAPReport tags below.
	    		//	Looks to be the same code
	    		String tempDateString = getBuilderText();
	    		log.debug("Attempting to get scan date from text '" + tempDateString + "'");
	    		
	    		String anchorString = "Report generated at ";
	    		if (tempDateString != null && !tempDateString.trim().isEmpty() && tempDateString.contains(anchorString)) {
	    			tempDateString = tempDateString.substring(tempDateString.indexOf(anchorString) + anchorString.length(),tempDateString.length()-2);
	    			testDate = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", tempDateString);
	    		
	    			if (testDate != null) {
	    				hasDate = true;
	    			}
	    		} else {
	    			log.debug("Date string appears to be empty or does not contain expected text: '" + anchorString + "'");
	    		}
	    		
	    		getDate = false;
	    	}
	    	
	    	if ("report".equals(qName)) {
	    		getDate = true;
	    		correctFormat = true;
	    	}

			if ("OWASPZAPReport".equals(qName)) {

				String tempDateString = atts.getValue("generated");
				log.debug("Attempting to get scan date from text '" + tempDateString + "'");

				String anchorString = "Report generated at ";
				if (tempDateString != null && !tempDateString.trim().isEmpty() && tempDateString.contains(anchorString)) {
					tempDateString = tempDateString.substring(tempDateString.indexOf(anchorString) + anchorString.length(),tempDateString.length()-2);
					testDate = getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss", tempDateString);

					if (testDate != null) {
						hasDate = true;
					}
				} else {
	    			log.debug("Date string appears to be empty or does not contain expected text: '" + anchorString + "'");
	    		}

				correctFormat = true;
			}

	    	if ("alertitem".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    @Override
		public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch,start,length);
	    	}
	    }
	}

	@Override
	public String getType() {
		return ScannerType.ZAPROXY.getFullName();
	}
}
