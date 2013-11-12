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

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.apache.commons.lang.StringEscapeUtils;
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
public class AppScanEnterpriseChannelImporter extends AbstractChannelImporter {
	
	@Override
	public String getType() {
		return ScannerType.APPSCAN_ENTERPRISE.getFullName();
	}
	
	private static Map<String, FindingKey> tagMap = new HashMap<>();
	static {
		tagMap.put("issue_type_name", FindingKey.VULN_CODE);
		tagMap.put("issue_severity", FindingKey.SEVERITY_CODE);
		tagMap.put("security_entity_element", FindingKey.PARAMETER);
		tagMap.put("test_url", FindingKey.PATH);
		tagMap.put("issue_id", FindingKey.NATIVE_ID);
	}

	public AppScanEnterpriseChannelImporter() {
		super(ScannerType.APPSCAN_DYNAMIC.getFullName());
	}
	
	/**
	 * This is added so we can use retrieveByName on the AppScan vulnerability mappings.
	 */
	@Override
	protected ChannelVulnerability getChannelVulnerability(String code) {
		if (channelType == null || code == null || channelVulnerabilityDao == null)
			return null;
		
		if (channelVulnerabilityMap == null)
			initializeMaps();

		if (channelVulnerabilityMap == null)
			return null;

		if (channelVulnerabilityMap.containsKey(code)) {
			return channelVulnerabilityMap.get(code);
		} else {
			ChannelVulnerability vuln = channelVulnerabilityDao.retrieveByName(channelType, code);
			if (vuln == null) {
				if (channelType != null)
					log.warn("A " + channelType.getName() + " channel vulnerability with code "
						+ StringEscapeUtils.escapeHtml(code) + " was requested but not found.");
				return null;
			} else {
				if (channelVulnerabilityDao.hasMappings(vuln.getId())) {
					log.info("The " + channelType.getName() + " channel vulnerability with code "
						+ StringEscapeUtils.escapeHtml(code) + " has no generic mapping.");
				}
			}

			channelVulnerabilityMap.put(code, vuln);
			return vuln;
		}
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new AppScanEnterpriseSAXParser());
	}
	
	public class AppScanEnterpriseSAXParser extends HandlerWithBuilder {
		
		private boolean getDate   = false;
		private boolean inFinding = false;
		
		private FindingKey itemKey = null;
	
		private Map<FindingKey, String> findingMap = null;
					    
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
	    	if ("row".equals(qName)) {
	    		findingMap = new EnumMap<>(FindingKey.class);
	    		inFinding = true;
	    	} else if (inFinding && tagMap.containsKey(qName)) {
	    		itemKey = tagMap.get(qName);
	    	}
	    }
	    
	    public void endElement (String uri, String name, String qName)
	    {
	    	if ("row".equals(qName)) {
	    		Finding finding = constructFinding(findingMap);
	    		
	    		finding.setNativeId(findingMap.get(FindingKey.NATIVE_ID));
	    		
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
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || itemKey != null) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

	@Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AppScanEnterpriseSAXValidator());
	}
	
	public class AppScanEnterpriseSAXValidator extends HandlerWithBuilder {
		
		private boolean report = false, control = false, row = false;
		
		private boolean hasFindings = false;
		private boolean correctFormat = false;
		
	    private void setTestStatus() {
	    	correctFormat = report && control && row;
	    	
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	
	    	if (testStatus == null) {
	    		if (!hasFindings)
		    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    		else 
	    			testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    	}
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("report".equals(qName)) {
	    		report = true;
	    	}
	    	
	    	if ("control".equals(qName)) {
	    		control = true;
	    	}
	    	
	    	if ("row".equals(qName)) {
	    		row = true;
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	}
}
