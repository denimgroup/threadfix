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

import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * 
 * @author mcollins
 */
@PluginImplementation
public class FindBugsChannelImporter extends AbstractChannelImporter {

	public FindBugsChannelImporter() {
		super(ScannerType.FINDBUGS.getFullName());
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
	    	if (start != null) {
	    		try {
	    			lineNum = Integer.valueOf(start);
	    		} catch (NumberFormatException e) {
	    			log.error("FindBugs had a non-integer value in its line number field.", e);
	    		}
	    	}
	    	
	    	if (lineNum == null) {
	    		lineNum = -1;
	    	}
	    	
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
	    			 dataFlowElements = new LinkedList<>();
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
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new FindBugsSAXValidator());
	}
	
	public class FindBugsSAXValidator extends DefaultHandler {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    }
	    
	    private ScanImportStatus checkTestDate() {
			if (applicationChannel == null || testDate == null)
				return ScanImportStatus.OTHER_ERROR;
			
			List<Scan> scanList = applicationChannel.getScanList();
			
			for (Scan scan : scanList) {
				if (scan != null && scan.getImportTime() != null) {
					int result = scan.getImportTime().compareTo(testDate);
					
					if (result == 0) {
						return ScanImportStatus.DUPLICATE_ERROR;
					} else if (result > 0) {
						return ScanImportStatus.OLD_SCAN_ERROR;
					} else if (scan.getImportTime().getTimeInMillis() % 1000 == 0
							&& (scan.getImportTime().getTimeInMillis() / 1000) ==
							   (testDate.getTimeInMillis() / 1000)){
						
						// MySQL doesn't support milliseconds. FindBugs does. 
						// This should make it work.
						
						return ScanImportStatus.DUPLICATE_ERROR;
					}
				}
			}
			
			log.info("Scan time compare returning success.");
			return ScanImportStatus.SUCCESSFUL_SCAN;
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
	    		
	    		hasDate = testDate != null;
	    		
	    		correctFormat = true;
	    	}
	    	
	    	if ("BugInstance".equals(qName) && "SECURITY".equals(atts.getValue("category"))) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}

	@Override
	public String getType() {
		return ScannerType.FINDBUGS.getFullName();
	}
}
