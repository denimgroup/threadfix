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

import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * 
 * @author mcollins
 */
public class FindBugsChannelImporter extends AbstractChannelImporter {

	@Autowired
	public FindBugsChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.FINDBUGS);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new FindBugsSAXParser());
	}
	
	private Calendar getCalendarFromTimeInMillisString(String timeInMillis) {
		try {
			Long timeLong = Long.valueOf(timeInMillis);
			Calendar calendar = Calendar.getInstance();
			calendar.setTimeInMillis(timeLong);
			return calendar;
		} catch (NumberFormatException e) {
			log.warn("Invalid date timestamp in FindBugs file.", e);
			return null;
		}
	}

	public class FindBugsSAXParser extends DefaultHandler {
		private Boolean inSecurityBug         = false;
		private Boolean getDataFlowElements   = false;
		
		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
		
		private List<DataFlowElement> dataFlowElements = null;
		private int dataFlowPosition;
					    
	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(true);
	    		saxFindingList.add(finding);
    		}
	    }
	    
	    public DataFlowElement getDataFlowElement(Attributes atts, int position) {
	    	String start = atts.getValue("start");
	    	Integer lineNum = null;
	    	if (start != null)
	    		lineNum = Integer.valueOf(start);
	    	
	    	return new DataFlowElement(null, lineNum, atts.getValue("sourcefile"), position);
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("BugCollection".equals(qName)) {
	    		String timeString = atts.getValue("timestamp");
	    		if (timeString != null) {
	    			date = getCalendarFromTimeInMillisString(timeString);
	    		}
	    	} else if ("BugInstance".equals(qName) && "SECURITY".equals(atts.getValue("category"))) {
	    		inSecurityBug = true;
	    		currentChannelVulnCode = atts.getValue("type");
	    		currentSeverityCode = atts.getValue("priority");
	    	} else if (inSecurityBug && "LocalVariable".equals(qName)) {
	    		currentParameter = atts.getValue("name");
	    	} else if (inSecurityBug && "SourceLine".equals(qName)) {
	    		 if (currentPath == null) {
	    			 currentPath = atts.getValue("sourcepath");
	    		 }
	    		 
	    		 if (getDataFlowElements) {
	    			 if (dataFlowElements != null) {
	    				 dataFlowElements.add(getDataFlowElement(atts,dataFlowPosition++));
	    			 }
	    		 }
	    		 
	    		 if ("SOURCE_LINE_GENERATED_AT".equals(atts.getValue("role"))) {
	    			 getDataFlowElements = true;
	    			 dataFlowElements = new LinkedList<DataFlowElement>();
	    			 dataFlowElements.add(getDataFlowElement(atts,0));
	    			 dataFlowPosition = 1;
	    		 }
	    	}
	    }

	    public void endElement (String uri, String name, String qName)
	    {
	    	if (inSecurityBug && "BugInstance".equals(qName)) {
	    		Finding finding = constructFinding(currentPath, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		
	    		finding.setDataFlowElements(dataFlowElements);
	    		
	    		add(finding);
	    		
	    		inSecurityBug = false;
	    		currentPath = null;
	    		currentParameter = null;
	    		currentChannelVulnCode = null;
	    		currentSeverityCode = null;
	    		dataFlowElements = null;
	    		dataFlowPosition = 0;
	    		getDataFlowElements = false;
	    	}
	    }
	}

	@Override
	public String checkFile() {
		return testSAXInput(new FindBugsSAXValidator());
	}
	
	public class FindBugsSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
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
	    	if ("BugCollection".equals(qName)) {
	    		String timeString = atts.getValue("timestamp");
	    		if (timeString != null) {
	    			testDate = getCalendarFromTimeInMillisString(timeString);
	    		}
	    		
	    		if (testDate != null)
	    			hasDate = true;
	    		correctFormat = true;
	    	}
	    	
	    	if ("BugInstance".equals(qName) && "SECURITY".equals(atts.getValue("category"))) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
