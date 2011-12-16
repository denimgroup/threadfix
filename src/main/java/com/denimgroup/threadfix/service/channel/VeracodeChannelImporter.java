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

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
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
 * Imports the results of a Veracode scan (xml output).
 * 
 * @author mcollins
 */
public class VeracodeChannelImporter extends AbstractChannelImporter {
	
	private boolean staticFlaws  = false;
		
	/**
	 * Constructor with Spring dependencies injected.
	 * 
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public VeracodeChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;

		setChannelType(ChannelType.VERACODE);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		return parseSAXInput(new VeracodeSAXParser());
	}
	
	
	public class VeracodeSAXParser extends DefaultHandler {	

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("detailedreport".equals(qName)) {
	    		date = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("last_update_time"));
	    		if (date == null)
	    			date = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("generation_date"));
	    	}
	    	
	    	if ("staticflaws".equals(qName)) 
	    		staticFlaws  = true;
	    	
	    	// TODO look through more Veracode scans and see if the inputvector component is the parameter.
	    	if ("flaw".equals(qName)) {
	    		if ("Fixed".equals(atts.getValue("remediation_status")))
	    			return;
	    		
	    		String url = null;
	    		if (atts.getValue("url") != null)
	    			url = atts.getValue("url");
	    		else if (atts.getValue("location") != null)
	    			url = atts.getValue("location");

	    		Finding finding = constructFinding(url,
	    										   atts.getValue("inputvector"),
	    										   atts.getValue("cweid"),
	    										   atts.getValue("severity"));
	    		if (finding != null) {
	    			finding.setNativeId(getNativeId(finding));
	    			
	    			// TODO revise this method of deciding whether the finding is static.	    			
	    			if (staticFlaws) {
	    				finding.setIsStatic(true);
	    				if (atts.getValue("sourcefile") != null && atts.getValue("sourcefilepath") != null) {
	    					String sourceFileLocation = atts.getValue("sourcefilepath") + atts.getValue("sourcefile");
	    					finding.setSourceFileLocation(sourceFileLocation);
	    					finding.getSurfaceLocation().setPath(sourceFileLocation);
	    					if (atts.getValue("line") != null) {
	    						DataFlowElement dataFlowElement = new DataFlowElement();
	    						dataFlowElement.setFinding(finding);
	    						dataFlowElement.setLineNumber(Integer.valueOf(atts.getValue("line")));
	    						dataFlowElement.setSourceFileName(sourceFileLocation);
	    						finding.setDataFlowElements(new ArrayList<DataFlowElement>());
	    						finding.getDataFlowElements().add(dataFlowElement);
	    					}
	    				}
	    			} else {
	    				finding.setIsStatic(false);
	    			}

	        		saxFindingList.add(finding);
	    		}
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName) {
	    	if ("staticflaws".equals(qName)) 
	    		staticFlaws  = false;
	    }
	}



	@Override
	public String checkFile() {
		return testSAXInput(new VeracodeSAXValidator());
	}
	
	public class VeracodeSAXValidator extends DefaultHandler {
		private boolean hasFindings = false, hasDate = false;
		private boolean detailedReport = false, flawStatus = false;
		private int severities = 0;
	    
	    private void setTestStatus() {
	    	boolean fileFormat = (detailedReport && flawStatus && (severities == 6));
	    	
	    	if (!fileFormat)
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

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("flaw".equals(qName))
	    		hasFindings = true;
	    	
	    	if ("detailedreport".equals(qName)) {
	    		testDate = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("last_update_time"));
	    		if (testDate == null)
	    			testDate = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("generation_date"));
	    		hasDate = testDate != null;
	    		detailedReport = true;
	    	}
	    	
	    	if (!flawStatus && "flaw-status".equals(qName))
	    		flawStatus = true;
	    	
	    	if ("severity".equals(qName))
	    		severities++;
	    }
	}
}
