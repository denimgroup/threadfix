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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.VulnerabilityMap;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * Imports the results of a dynamic AppScan scan.
 * 
 * @author mcollins
 */
public class AppScanWebImporter extends AbstractChannelImporter {

	/**
	 * Constructor with Spring dependencies injected.
	 * 
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param genericVulnerabilityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public AppScanWebImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			GenericVulnerabilityDao genericVulnerabilityDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.genericVulnerabilityDao = genericVulnerabilityDao;

		setChannelType(ChannelType.APPSCAN_DYNAMIC);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		return parseSAXInput(new AppScanSAXParser());
	}
	
	public class AppScanSAXParser extends DefaultHandler {
		
		private ChannelVulnerability currentChannelVuln = null;
		private ChannelSeverity currentChannelSeverity  = null;
		
		private String currentUrl = null;
		private String currentParam = null;
		private String currentIssueTypeId = null;
		private String requestText = null;
		
		private final Map<String, ChannelSeverity> severityMap;
		private final Map<String, String> genericVulnMap;
		private final Map<String, String> channelVulnNameMap;
						
		private boolean grabUrlText       = false;
		private boolean grabSeverity      = false;
		private boolean grabCWE           = false;
		private boolean grabIssueTypeName = false;
		private boolean issueTypes        = true;
		private boolean grabDate          = false;

	    public AppScanSAXParser () {
	    	super();
	    	
	    	hosts = new ArrayList<String>();
	    	severityMap = new HashMap<String, ChannelSeverity>();
	    	genericVulnMap = new HashMap<String, String>();
	    	channelVulnNameMap = new HashMap<String, String>();
	    }
	    
	    private void addChannelVulnsAndMappingsToDatabase() {
	    	for (String key : genericVulnMap.keySet()) {
	    		ChannelVulnerability channelVuln = getChannelVulnerability(key);
	    		
	    		if (channelVuln == null) {
	    			channelVuln = new ChannelVulnerability();
	    			channelVuln.setCode(key);
	    			channelVuln.setName(channelVulnNameMap.get(key));
	    			channelVuln.setChannelType(channelType);
	    		} else if (channelVuln.getVulnerabilityMaps() != null
						&& channelVuln.getVulnerabilityMaps().size() != 0) {
	    			return;
				}
	    		
	    		GenericVulnerability genericVuln = null;
	    		if (genericVulnMap.get(key).matches("[0-9]+"))
		    		genericVuln = genericVulnerabilityDao.retrieveById(Integer.valueOf(genericVulnMap.get(key)));
	    		
	    		if (genericVuln != null)
	    			createVulnRelationship(channelVuln, genericVuln);
	    	
	    		channelVulnerabilityDao.saveOrUpdate(channelVuln);
	    		channelVulnerabilityMap.put(key, channelVuln);
	    	} 
	    }
	    
	    /**
		 * Tie a channel vuln and generic vuln together with a vulnerability map.
		 * 
		 * @param channelVuln
		 * @param genericVuln
		 */
		private void createVulnRelationship(ChannelVulnerability channelVuln,
				GenericVulnerability genericVuln) {
			
			if (channelVuln == null || genericVuln == null)
				return;

			VulnerabilityMap vm = new VulnerabilityMap();
			vm.setChannelVulnerability(channelVuln);
			vm.setGenericVulnerability(genericVuln);
			List<VulnerabilityMap> vulnerabilityMapList = new ArrayList<VulnerabilityMap>();
			vulnerabilityMapList.add(vm);
			channelVuln.setVulnerabilityMaps(vulnerabilityMapList);
			genericVuln.setVulnerabilityMaps(vulnerabilityMapList);
		}

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("Host".equals(qName))
	    		hosts.add(atts.getValue(0));
	    	
	    	if (issueTypes) {
	    		// ISSUETYPE
	    		if ("IssueType".equals(qName))
	    			currentIssueTypeId = atts.getValue(0);
	    		else if ("Severity".equals(qName))
	    			grabSeverity = true;
	    		else if ("link".equals(qName))
	    			grabCWE = true;
	    		else if ("Issues".equals(qName))
	    			issueTypes = false;
	    		else if ("name".equals(qName))
	    			grabIssueTypeName = true;
	    			    	
	    	} else {
		    	if ("Issue".equals(qName)) {
		    		currentChannelVuln = getChannelVulnerability(atts.getValue(0));
		    		currentChannelSeverity = severityMap.get(atts.getValue(0));
		    	}
		    	else if ("Entity".equals(qName) && atts.getValue(1) != null && atts.getValue(1).trim().equals("Parameter"))
		    		currentParam = atts.getValue(0);
		    	else if ("Url".equals(qName))
		    		grabUrlText = true;
		    	else if (date == null && "OriginalHttpTraffic".equals(qName)) {
		    		requestText = "";
		    		grabDate = true;
		    	}
	    	}
	    }

	    public void endElement (String uri, String name, String qName) throws SAXException {	    	
	    	if ("Issues".equals(qName)) {
				throw new SAXException("Done Parsing.");
	    	} else if ("IssueTypes".equals(qName)) {
	    		addChannelVulnsAndMappingsToDatabase();
	    	} else if ("Issue".equals(qName)) {
	    		Finding finding = new Finding();
	    		SurfaceLocation location = new SurfaceLocation();
	    		
	    		for (String host : hosts)
	    			if (currentUrl.startsWith(host)) {
	    				location.setHost(host);
		    			location.setPath("/" + currentUrl.substring(host.length()));
	    			}
	    		
	    		if (location.getPath() == null)
	    			location.setPath(currentUrl);
	    		
	    		location.setParameter(currentParam);
	    		
	    		finding.setSurfaceLocation(location);
	    		finding.setChannelVulnerability(currentChannelVuln);
	    		finding.setChannelSeverity(currentChannelSeverity);
	    		
	    		finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);
	    		
	    		saxFindingList.add(finding);
	    	
	    		currentChannelVuln = null;
	    		currentUrl = null;
	    		currentParam = null;
	    		
	    	} else if (date == null && "OriginalHttpTraffic".equals(qName)) {
	    		date = attemptToParseDateFromHTTPResponse(requestText);
	    		grabDate = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (grabUrlText) {
	    		currentUrl = getText(ch, start, length);
	    		grabUrlText = false;
	    		
	    	} else if (grabSeverity) {
	    		String severityString = getText(ch, start, length);
	    		ChannelSeverity severity = getChannelSeverity(severityString);
	    		
	    		if (currentIssueTypeId != null && severity != null)
	    			severityMap.put(currentIssueTypeId, severity);
	    		
	    		grabSeverity = false;
	    	} else if (grabCWE) {
	    		String maybeId = getText(ch, start, length);
	    		
	    		if (maybeId.startsWith("CWE-") && maybeId.contains(":")) {
	    			maybeId = maybeId.substring(4, maybeId.indexOf(':'));
		    		genericVulnMap.put(currentIssueTypeId, maybeId);
	    		}
	    		
	    		grabCWE = false;
	    	} else if (grabIssueTypeName) {
	    		String charString = getText(ch,start,length);
	    		channelVulnNameMap.put(currentIssueTypeId, charString);
	    		
	    		grabIssueTypeName = false;
	    	} else if (grabDate) {
	    		requestText = requestText.concat(getText(ch, start, length));
		  	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AppScanSAXValidator());
	}
	
	public class AppScanSAXValidator extends DefaultHandler {
		private boolean hasFindings = false, hasDate = false;
		private boolean xmlReport = false, appscanInfo = false,
			summary = false, results = false;
		
		private String requestText;
		
		private boolean grabDate;
	    
	    private void setTestStatus() {
	    	boolean fileFormat = (xmlReport && appscanInfo && summary && results);
	    	
	    	if (!fileFormat)
	    		testStatus = WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((!hasDate || SUCCESSFUL_SCAN.equals(testStatus)) && !hasFindings)
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
	    	if ("Issue".equals(qName))
	    		hasFindings = true;
	    	
	    	if (!hasDate && "OriginalHttpTraffic".equals(qName)) {
	    		requestText = "";
	    		grabDate = true;
	    	}
	    	
	    	if (!xmlReport && "XmlReport".equals(qName))
	    		xmlReport = true;
	    	if (!appscanInfo && "AppScanInfo".equals(qName))
	    		appscanInfo = true;
	    	if (!summary && "Summary".equals(qName))
	    		summary = true;
	    	if (!results && "Results".equals(qName))
	    		results = true;
	    	if ("ApplicationData".equals(qName)) {
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }

	    public void endElement (String uri, String name, String qName){
	    	if (!hasDate && "OriginalHttpTraffic".equals(qName)) {
	    		testDate = attemptToParseDateFromHTTPResponse(requestText);
	    		grabDate = false;
	    		if (testDate != null)
	    			hasDate = true;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (grabDate)
	    		requestText = requestText.concat(getText(ch, start, length));
	    }
	}

}
