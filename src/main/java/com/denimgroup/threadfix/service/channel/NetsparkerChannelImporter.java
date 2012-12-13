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
 *
 */
public class NetsparkerChannelImporter extends AbstractChannelImporter {

	@Autowired
	public NetsparkerChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.channelType = channelTypeDao.retrieveByName(ChannelType.NETSPARKER);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		return parseSAXInput(new NetsparkerSAXParser());
	}

	public class NetsparkerSAXParser extends HandlerWithBuilder {
		private Boolean getChannelVulnText    = false;
		private Boolean getUrlText            = false;
		private Boolean getParamText          = false;
		private Boolean getSeverityText       = false;
		
		private String currentChannelVulnCode = null;
		private String currentUrlText         = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
				
		private String host = null;
	    
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
	    	if ("type".equals(qName)) {
	    		getChannelVulnText = true;
	    	} else if ("url".equals(qName)) {
	    		getUrlText = true;
	    	} else if ("vulnerableparameter".equals(qName)) {
	    		getParamText = true;
	    	} else if ("severity".equals(qName)) {
	    		getSeverityText = true;
	    	} else if ("netsparker".equals(qName)) {
	    		date = getCalendarFromString("MM/dd/yyyy hh:mm:ss a", atts.getValue("generated"));
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if (getChannelVulnText) {
	    		currentChannelVulnCode = getBuilderText();
	    		getChannelVulnText = false;
	    	} else if (getUrlText) {
	    		if (host == null)
	    			host = getBuilderText();
	    		else
		    		currentUrlText = getBuilderText();
	    		getUrlText = false;
	    	} else if (getParamText) {
	    		currentParameter = getBuilderText();
	    		getParamText = false;
	    	} else if (getSeverityText) {
	    		currentSeverityCode = getBuilderText();
	    		getSeverityText = false;
	    	}
	    	
	    	if ("vulnerability".equals(qName)) {
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
	    	if (getChannelVulnText || getUrlText || getParamText || getSeverityText) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new NetsparkerSAXValidator());
	}
	
	public class NetsparkerSAXValidator extends DefaultHandler {
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

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("netsparker".equals(qName)) {
	    		testDate = getCalendarFromString("MM/dd/yyyy hh:mm:ss a", atts.getValue("generated"));
	    		if (testDate != null)
	    			hasDate = true;
	    		correctFormat = true;
	    	}
	    	
	    	if ("vulnerability".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
