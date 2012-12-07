////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
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

import java.util.HashMap;
import java.util.Map;

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
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
public class NTOSpiderChannelImporter extends AbstractChannelImporter {
	
	private static Map<String, String> tagMap = new HashMap<String, String>();
	static {
		tagMap.put("VULNTYPE", CHANNEL_VULN_KEY);
		tagMap.put("ATTACKSCORE", CHANNEL_SEVERITY_KEY);
		tagMap.put("PARAMETERNAME", PARAMETER_KEY);
		tagMap.put("NORMALIZEDURL", PATH_KEY);
	}

	@Autowired
	public NTOSpiderChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.channelType = channelTypeDao.retrieveByName(ChannelType.NTO_SPIDER);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new NTOSaxParser());
	}
	
	public class NTOSaxParser extends DefaultHandler {
		
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
	    	if (date == null && "SCANDATE".equals(qName)) {
	    		getDate = true;
	    	} else if ("VULN".equals(qName)) {
	    		findingMap = new HashMap<String, String>();
	    		inFinding = true;
	    	} else if (inFinding && tagMap.containsKey(qName)) {
	    		itemKey = tagMap.get(qName);
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("VULN".equals(qName)) {
	    		
	    		if (findingMap.get(PARAMETER_KEY) != null && findingMap.get(PARAMETER_KEY).equals("N/A")) {
	    			findingMap.remove(PARAMETER_KEY);
	    		}
	    		
	    		Finding finding = constructFinding(findingMap);
	    		
	    		add(finding);
	    		findingMap = null;
	    		inFinding = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = getCalendarFromString("yyyy-MM-dd kk:mm:ss", tempDateString);
	    		}
	    		getDate = false;
	    	} else if (itemKey != null) {
	    		findingMap.put(itemKey, getText(ch,start,length));
	    		itemKey = null;
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new NTOSaxValidator());
	}
	
	public class NTOSaxValidator extends DefaultHandler {
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

	    @Override
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("VULNLIST".equals(qName)) {
	    		correctFormat = true;
	    	}
	    	
	    	if (testDate == null && "SCANDATE".equals(qName)) {
	    		getDate = true;
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String name, String qName) throws SAXException {	    	
	    	if ("VULN".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			testDate = getCalendarFromString("yyyy-MM-dd kk:mm:ss", tempDateString);
	    		}
	    		
	    		hasDate = testDate != null;
	    		getDate = false;
	    	}
	    }
	}
}
