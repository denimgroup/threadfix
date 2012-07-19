////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

/**
 * Imports the results of a WebInspect scan (xml output).
 * 
 * Parses the 
 * 
 * Export -> Details -> Full
 * 
 * format, and none of the others.
 * 
 * @author mcollins
 */
public class WebInspectChannelImporter extends AbstractChannelImporter {
	
	private String bestPractices = "Best Practices";
		
	/**
	 * Constructor with Spring dependencies injected.
	 * 
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public WebInspectChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, 
			ChannelSeverityDao channelSeverityDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		
		setChannelType(ChannelType.WEBINSPECT);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		return parseSAXInput(new WebInspectSAXParser());
	}
	
	public class WebInspectSAXParser extends DefaultHandler {
		
		private String currentChannelVulnName;
		private String currentUrl;
		private String currentParam;
		private String currentChannelSeverityName;
		private String currentResponseText;

		private boolean grabUrlText       = false;
		private boolean grabVulnNameText  = false;
		private boolean grabSeverityText  = false;
		private boolean grabParameterText = false;
		private boolean grabDate          = false;
		private boolean grabTypeId        = false;
		
		private boolean ignoreFinding     = false;
		
		private boolean issues = false;
		
		private final String [] paramChars = { "[", "]", "%" };
			 	
	 	private String cleanParam(String param){
	 		if (param == null || param.isEmpty())
	 			return null;
	 		
	 		String editedParam = param;
	 		
	 		for (String character : paramChars)
	 			if (editedParam.contains(character))
	 				editedParam = editedParam.substring(0, editedParam.indexOf(character));

	 		return editedParam;
	 	}
	    
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
	    	if ("Issues".equals(qName))
	    		issues = true;
	    	
	    	if (issues) {
	    		if ("Name".equals(qName)) {
	    			if (currentChannelVulnName == null)
	    				grabVulnNameText = true;
	    		} else if ("Severity".equals(qName)) {
	    			grabSeverityText = true;
	    		} else if ("CheckTypeID".equals(qName)) {
		    		grabTypeId = true;
		    	}
	    		
	    	} else {
	    		if ("URL".equals(qName)) {
	    			grabUrlText = true;
	    		} else if ("AttackParamDescriptor".equals(qName)) {
		    		grabParameterText = true;
		    	}
	    	}
	    	
	    	if (date == null && "RawResponse".equals(qName))
	    		grabDate = true;
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("Issues".equals(qName))
	    		issues = false;
	    	
	    	if ("AttackParamDescriptor".equals(qName))
	    		grabParameterText = false;
	    	
	    	if ("Issue".equals(qName)) {
	    		if (currentUrl == null)
	    			return;
	    		
	    		if (!ignoreFinding) {
	    			Finding finding = constructFinding(currentUrl, currentParam, 
		    				currentChannelVulnName, currentChannelSeverityName);

		    		add(finding);
	    		}
		
	    		currentChannelSeverityName = null;
	    		currentChannelVulnName = null;
	    		currentParam = null;
	    		currentUrl = null;
	    		ignoreFinding = false;
	    	}
	    	
	    	if (grabDate && "RawResponse".equals(qName)) {
	    		grabDate = false;
	    		date = attemptToParseDateFromHTTPResponse(currentResponseText);
	    		currentResponseText = "";
	    	}
	    }

	    public void characters (char ch[], int start, int length)
	    {
	    	if (grabUrlText) {
	    		currentUrl = getText(ch, start, length);
	    		grabUrlText = false;
	    	
	    	} else if (grabVulnNameText) {
	    		currentChannelVulnName = getText(ch, start, length);
	    		grabVulnNameText = false;
	    	
	    	} else if (grabSeverityText) {
	    		currentChannelSeverityName = getText(ch, start, length);
	    		grabSeverityText = false;
	    		
	    	} else if (grabParameterText) {
	    		currentParam = getText(ch, start, length);
	    		
	    		// TODO decide whether or not to clean out the various [] and %5d characters
	    		// that are sometimes tacked on. Right now we do.
	    		currentParam = cleanParam(currentParam);
	    		grabParameterText = false;
	    	} else if (grabDate) {
	    		if (currentResponseText == null)
	    			currentResponseText = getText(ch, start, length);
	    		else
	    			currentResponseText = currentResponseText.concat(getText(ch, start, length));
	    	} else if (grabTypeId) {
	    		String temp = getText(ch, start, length).trim();
	    		ignoreFinding = temp.equals(bestPractices);
	    		grabTypeId = false;
	    	}
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new WebInspectSAXValidator());
	}
	
	public class WebInspectSAXValidator extends DefaultHandler {
		private boolean hasFindings = false, hasDate = false, correctFormat = false;
		private boolean grabDate = false;
		private String currentResponseText = null;
				
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	else if (!hasFindings)
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

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("Session".equals(qName))
	    		hasFindings = true;
	    	
	    	if (!correctFormat && "Sessions".equals(qName))
	    		correctFormat = true;
	    	
	    	if (!hasDate && "RawResponse".equals(qName))
	    		grabDate = true;
	    }
	    
	    public void endElement (String uri, String name, String qName) throws SAXException
	    {
	    	if (!hasDate && grabDate && "RawResponse".equals(qName)) {
	    		grabDate = false;
	    		testDate = attemptToParseDateFromHTTPResponse(currentResponseText);
	    		hasDate = testDate != null;
	    		currentResponseText = "";
	    		if (hasDate && hasFindings && correctFormat) {
	    			setTestStatus();
	    			throw new SAXException(FILE_CHECK_COMPLETED);
	    		}
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length)
	    {
	    	if (grabDate) {
	    		if (currentResponseText == null)
	    			currentResponseText = getText(ch, start, length);
	    		else
	    			currentResponseText = currentResponseText.concat(getText(ch, start, length));
	    	}
	    }
	}
}
