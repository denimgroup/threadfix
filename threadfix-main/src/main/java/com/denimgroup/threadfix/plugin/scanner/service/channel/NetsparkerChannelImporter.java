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
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
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
public class NetsparkerChannelImporter extends AbstractChannelImporter {

	public NetsparkerChannelImporter() {
		super(ScannerType.NETSPARKER.getFullName());
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
	    		
	    		// The old XML format didn't include severities. As severities are required
	    		// for vulnerabilities to show on the application page, let's assign medium 
	    		// severity. This is only known to affect beta versions of Netsparker.
	    		if (finding != null && finding.getChannelSeverity() == null) {
	    			ChannelSeverity mediumChannelSeverity = channelSeverityDao.retrieveByCode(channelType, "Medium");
	    			finding.setChannelSeverity(mediumChannelSeverity);
	    		}

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

	@Override
	public String getType() {
		return ScannerType.NETSPARKER.getFullName();
	}
}
