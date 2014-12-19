////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Imports the results of a dynamic AppScan scan.
 * 
 * @author mcollins
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.APPSCAN_DYNAMIC_DB_NAME,
        startingXMLTags = { "XmlReport", "AppScanInfo", "Version", "ServicePack", "Summary", "TotalIssues" })
public class AppScanWebImporter extends AbstractChannelImporter {

	public AppScanWebImporter() {
		super(ScannerType.APPSCAN_DYNAMIC);
	}

	/*
	 * (non-Javadoc)
	 * @see
	 * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
	 */
	@Override
	public Scan parseInput() {
		return parseSAXInput(new AppScanSAXParser());
	}
	
	public class AppScanSAXParser extends HandlerWithBuilder {

        Map<FindingKey, String> findingMap = new HashMap<>();

        private ChannelVulnerability currentChannelVuln = null;
		private ChannelSeverity currentChannelSeverity  = null;
		
		private String currentUrl = null;
		private String currentParam = null;
		private String currentIssueTypeId = null;
		private String requestText = null;
		private String currentHttpMethod = null;
        private String currentScannerDetail   = null;
        private String currentAttackDetail = null;
        private String currentRequestResponse         = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();
		
		private final Map<String, ChannelSeverity> severityMap = new HashMap<>();
		private final Map<String, String> genericVulnMap = new HashMap<>();
		private final Map<String, String> channelVulnNameMap = new HashMap<>();
						
		private boolean grabUrlText       = false;
		private boolean grabSeverity      = false;
		private boolean grabCWE           = false;
		private boolean grabIssueTypeName = false;
		private boolean inIssueTypes = true;
		private boolean grabDate          = false;
        private boolean grabRequestResponseText		  = false;
        private boolean grabAttackDetail       = false;
        private boolean grabScannerDetail      = false;
        private boolean inFinding		  = false;

	    public AppScanSAXParser () {
	    	super();
	    	
	    	hosts = list();
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
		    		genericVuln = genericVulnerabilityDao.retrieveByDisplayId(Integer.valueOf(genericVulnMap.get(key)));
	    		
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

			VulnerabilityMap vulnerabilityMap = new VulnerabilityMap();
			vulnerabilityMap.setChannelVulnerability(channelVuln);
			vulnerabilityMap.setGenericVulnerability(genericVuln);
			List<VulnerabilityMap> vulnerabilityMapList = list();
			vulnerabilityMapList.add(vulnerabilityMap);
			channelVuln.setVulnerabilityMaps(vulnerabilityMapList);
			genericVuln.setVulnerabilityMaps(vulnerabilityMapList);
		}

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("Host".equals(qName))
	    		hosts.add(atts.getValue(0));
	    	
	    	if (inIssueTypes) {
	    		
	    		switch (qName) {
	    			case "IssueType" : currentIssueTypeId = atts.getValue(0); break;
	    			case "Issue"     : inIssueTypes = false;                  break;
	    			case "Severity"  : grabSeverity = true;                   break;
	    			case "link"      : grabCWE = true;                        break;
	    			case "name"      : grabIssueTypeName = true;              break;
	    		}
	    			    	
	    	} else {
		    	if ("Issue".equals(qName)) {
		    		currentChannelVuln = getChannelVulnerability(atts.getValue(0));
		    		currentChannelSeverity = severityMap.get(atts.getValue(0));
                    inFinding = true;
		    	}
		    	else if ("Entity".equals(qName))
		    		currentParam = atts.getValue("Name");
		    	else if ("Url".equals(qName))
		    		grabUrlText = true;
		    	else if ("OriginalHttpTraffic".equals(qName)) {
		    		requestText = "";
		    		grabDate = true;
		    	} else if ("Difference".equals(qName)) {
                    grabAttackDetail = true;
                } else if ("Reasoning".equals(qName)) {
                    grabScannerDetail = true;
                } else if ("TestHttpTraffic".equals(qName)) {
                    grabRequestResponseText = true;
                }
	    	}
            if (inFinding){
                currentRawFinding.append(makeTag(name, qName , atts));
            }
	    }

	    public void endElement (String uri, String name, String qName) throws SAXException {
	    	if (grabUrlText) {
	    		currentUrl = getBuilderText();
	    		grabUrlText = false;
	    		
	    	} else if (grabSeverity) {
	    		String severityString = getBuilderText();
	    		ChannelSeverity severity = getChannelSeverity(severityString);
	    		
	    		if (currentIssueTypeId != null && severity != null)
	    			severityMap.put(currentIssueTypeId, severity);
	    		
	    		grabSeverity = false;
	    	} else if (grabCWE) {
	    		String maybeId = getBuilderText();
	    		
	    		if (maybeId.startsWith("CWE-") && maybeId.contains(":")) {
	    			maybeId = maybeId.substring(4, maybeId.indexOf(':'));
		    		genericVulnMap.put(currentIssueTypeId, maybeId);
	    		}
	    		
	    		grabCWE = false;
	    	} else if (grabIssueTypeName) {
	    		String charString = getBuilderText();
	    		channelVulnNameMap.put(currentIssueTypeId, charString);
	    		
	    		grabIssueTypeName = false;
	    	} else if (grabDate) {
	    		requestText = requestText.concat(getBuilderText());
		  	} else if (grabAttackDetail) {
                currentAttackDetail = getBuilderText();
                grabAttackDetail = false;
            } else if (grabScannerDetail) {
                currentScannerDetail = getBuilderText();
                grabScannerDetail = false;
            } else if (grabRequestResponseText) {
                currentRequestResponse = getBuilderText();
                grabRequestResponseText = false;
            }

            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }
	    	
	    	if ("Issues".equals(qName)) {
				throw new SAXException("Done Parsing.");
	    	} else if ("IssueTypes".equals(qName)) {
	    		addChannelVulnsAndMappingsToDatabase();
                inIssueTypes = false;
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
	    		location.setHttpMethod(currentHttpMethod);
	    		
	    		finding.setSurfaceLocation(location);
	    		finding.setChannelVulnerability(currentChannelVuln);

                finding.setChannelSeverity(currentChannelSeverity);

	    		finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);

                findingMap.put(FindingKey.REQUEST, currentRequestResponse);
                findingMap.put(FindingKey.VALUE, currentAttackDetail);
                findingMap.put(FindingKey.DETAIL, currentScannerDetail);
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
                addFindingDetail(finding, findingMap);
	    		
	    		saxFindingList.add(finding);
	    	
	    		currentChannelVuln = null;
	    		currentUrl = null;
	    		currentParam = null;
	    		currentHttpMethod = null;
                currentScannerDetail   = null;
                currentAttackDetail = null;
                currentRequestResponse         = null;
                currentRawFinding.setLength(0);
                inFinding = false;

	    		
	    	} else if ("OriginalHttpTraffic".equals(qName)) {
	    		if (date == null) {
	    			date = DateUtils.attemptToParseDateFromHTTPResponse(requestText);
	    		}
	    		currentHttpMethod = parseHttpMethodFromHttpResponse(requestText);
	    		grabDate = false;
	    	}
	    }

	    private String parseHttpMethodFromHttpResponse(String requestText) {
	    	String returnHttpMethod = null;
	    	
			if (requestText != null) {
				for (String httpMethod : SurfaceLocation.REQUEST_METHODS) {
					if (requestText.startsWith(httpMethod)) {
						returnHttpMethod = httpMethod;
					}
				}
			}
			
			return returnHttpMethod;
		}

		public void characters (char ch[], int start, int length) {
	    	if (grabUrlText || grabSeverity || grabCWE || grabIssueTypeName || grabDate
                    || grabRequestResponseText || grabAttackDetail || grabScannerDetail) {
	    		addTextToBuilder(ch, start, length);
	    	}
            if (inFinding)
                currentRawFinding.append(ch,start,length);
	    }
	}

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new AppScanSAXValidator());
	}
	
	public class AppScanSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false, hasDate = false;
		private boolean xmlReport = false, appscanInfo = false,
			summary = false, results = false;
		
		private String requestText;
		
		private boolean grabDate;
	    
	    private void setTestStatus() {
	    	boolean fileFormat = (xmlReport && appscanInfo && summary && results);
	    	
	    	if (!fileFormat) {
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    		return;
	    	} else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((!hasDate || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings)
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
	    	if (grabDate) {
	    		requestText = getBuilderText();
	    		grabDate = false;
	    	}
	    	
	    	if (!hasDate && "OriginalHttpTraffic".equals(qName)) {
	    		testDate = DateUtils.attemptToParseDateFromHTTPResponse(requestText);
	    		grabDate = false;
	    		if (testDate != null)
	    			hasDate = true;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (grabDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

}
