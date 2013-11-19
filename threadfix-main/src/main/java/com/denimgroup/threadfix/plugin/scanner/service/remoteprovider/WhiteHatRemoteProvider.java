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
package com.denimgroup.threadfix.plugin.scanner.service.remoteprovider;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.plugin.scanner.service.channel.HandlerWithBuilder;
import com.denimgroup.threadfix.service.ScanUtils;

@PluginImplementation
public class WhiteHatRemoteProvider extends RemoteProvider {

	@Override
	public String getType() {
		return ScannerType.SENTINEL.getFullName();
	}
	private static final String SITES_URL = "https://sentinel.whitehatsec.com/api/site/";
	private static final String VULNS_URL = "https://sentinel.whitehatsec.com/api/vuln/";
	private static final String EXTRA_PARAMS = "&display_attack_vectors=1&query_site=";
	
	private String apiKey = null;
	
	private List<Calendar> scanDateList = null;
	private Map<Finding, List<DateStatus>> findingDateStatusMap = null;
	

	@Autowired
	public WhiteHatRemoteProvider() {
		super(ScannerType.SENTINEL.getFullName());
	}

	@Override
	public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
		log.info("Retrieving a WhiteHat scan.");

		apiKey = remoteProviderApplication.getRemoteProviderType().getApiKey();
		
		InputStream labelSiteIdStream = httpGet(SITES_URL + "?key=" + apiKey);
		
		if (labelSiteIdStream == null) {
			log.warn("Received a bad response from WhiteHat servers, returning null.");
			return null;
		}
		
		String appName = remoteProviderApplication.getNativeId();
		
		WhiteHatSitesParser parser = new WhiteHatSitesParser();
		
		parse(labelSiteIdStream, parser);
		
		String siteId = parser.map.get(appName);
		if (siteId == null) {
			log.warn("No build ID was parsed.");
			return null; // we failed.
		} else {
			log.info("Retrieved build ID " + siteId + " for application " + appName);
		}
		
		String url = VULNS_URL + "?key=" + apiKey + EXTRA_PARAMS + siteId;
		
		log.info("Requesting site ID " + siteId);

		inputStream = httpGet(url);
		
		if (inputStream == null) {
			log.warn("Received a bad response from WhiteHat servers, returning null.");
			return null;
		}

		WhiteHatVulnerabilitiesParser scanParser = new WhiteHatVulnerabilitiesParser();
		List<Scan> scans = parseSAXInputWhiteHat(scanParser);
		
		if (scans == null || scans.size() == 0) {
			log.warn("No scan was parsed, returning null.");
			return null;
		}
		
		for (Scan resultScan : scans)
			resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
		
		log.info("WhiteHat "+ scans.size() +" scans successfully parsed.");
		
		return filterScans(scans);
	}

	/**
	 * This method checks if there are 2 scans with consecutive imported dates and same finding list. If any, remove the earlier one.
	 * @param scans
	 * @return
	 */
	private List<Scan> filterScans(List<Scan> scans) {
		List<Scan> resultList = new ArrayList<>();
		for (Scan s: scans) 
			resultList.add(s);
		for (int i=0;i<scans.size()-1;i++) {
			Scan scan1 = scans.get(i);
			Calendar date1 = scan1.getImportTime();
			Scan scan2 = scans.get(i+1);
			Calendar date2 = scan2.getImportTime();
			
			// Checking if they have consecutive imported dates
			if ((date2.getTimeInMillis()-date1.getTimeInMillis())/(24*60*60*1000)==1) {
				if (scan1.getFindings().size() == scan2.getFindings().size()) {
					boolean isDuplicatedScan = true;
					List<Finding> findingList1 = scan1.getFindings();
					List<Finding> findingList2 = scan2.getFindings();

					for (Finding f: findingList1) {
						if (!findingList2.contains(f)) {
							isDuplicatedScan = false;
							break;
						}
					}
					if (isDuplicatedScan) resultList.remove(scan1);
				}
			}
		}
		return resultList;
	}

	@Override
	public List<RemoteProviderApplication> fetchApplications() {
		if (remoteProviderType == null || remoteProviderType.getApiKey() == null) {
			log.warn("Insufficient credentials.");
			return null;
		}
		
		apiKey = remoteProviderType.getApiKey();
		
		WhiteHatSitesParser parser = new WhiteHatSitesParser();
		
		InputStream stream = httpGet(SITES_URL + "?key=" + apiKey);

		parse(stream, parser);
		
		return parser.getApplications();
	}
	
	public InputStream httpGet(String urlStr) {
		GetMethod get = new GetMethod(urlStr);
		
		InputStream responseStream = null;
		
		HttpClient client = new HttpClient();
		try {
			int status = client.executeMethod(get);
			if (status != 200) {
				log.warn("Request status was not 200. It was " + status);
			}
			
			responseStream = get.getResponseBodyAsStream();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return responseStream;
	}
	
	/**
	 * This method parses input file to list of scan
	 * @param handler
	 * @return
	 */
	private List<Scan> parseSAXInputWhiteHat(DefaultHandler handler) {
		log.debug("Starting WhiteHat SAX Parsing.");
		
		if (inputStream == null)
			return null;
		
		List<Scan> scanList = new ArrayList<>();
		
		ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);
		Collections.sort(scanDateList);
		
		for (Calendar d : scanDateList) {
			date = d;
			saxFindingList = new ArrayList<>();
			for (Finding finding : findingDateStatusMap.keySet()) {
				List<DateStatus> dateInfo = findingDateStatusMap.get(finding);
				Collections.sort(dateInfo);
				boolean isAdded = false;

				// Checking if Finding is open at this time
				for (int i=0;i<dateInfo.size()-1;i++){
					if (date.compareTo(dateInfo.get(i).getDate())>=0 && date.compareTo(dateInfo.get(i+1).getDate())<0) {
						if (dateInfo.get(i).getStatus().equals("open")) {
							saxFindingList.add(finding);
							isAdded = true;
							break;
						}
					}
				}
				if (!isAdded) {
					if (date.compareTo(dateInfo.get(dateInfo.size()-1).getDate())>=0 
							&& dateInfo.get(dateInfo.size()-1).getStatus().equals("open"))
						saxFindingList.add(finding);
				}
			}
			
			scanList.add(makeNewScan());
		}
		
		return scanList;
	}
	
	private Scan makeNewScan() {
		Scan scan = new Scan();
		scan.setFindings(saxFindingList);
		scan.setApplicationChannel(applicationChannel);
		
		if ((date != null) && (date.getTime() != null)) {
			log.debug("SAX Parser found the scan date: " + date.getTime().toString());
			scan.setImportTime(date);
		} else {
			log.warn("SAX Parser did not find the date.");
		}

		if (scan.getFindings() != null && scan.getFindings().size() != 0)
			log.debug("SAX Parsing successfully parsed " + scan.getFindings().size() +" Findings.");
		else
			log.warn("SAX Parsing did not find any Findings.");
		
		return scan;
	}

	public class WhiteHatSitesParser extends HandlerWithBuilder {
		
		public Map<String, String> map = new HashMap<>();
		
		private String currentId = null;
		private boolean grabLabel;
		
		public List<RemoteProviderApplication> getApplications() {
			List<RemoteProviderApplication> apps = new ArrayList<>();
			for (String label : map.keySet()) {
				RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
	    		remoteProviderApplication.setNativeId(label);
	    		remoteProviderApplication.setRemoteProviderType(remoteProviderType);
	    		apps.add(remoteProviderApplication);
			}
			return apps;
		}
		
	    public void startElement(String uri, String name, String qName, Attributes atts) throws SAXException {
	    	if ("site".equals(qName)) {
	    		currentId = atts.getValue("id");
	    	} else if ("label".equals(qName)) {
	    		grabLabel = true;
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (grabLabel) {
	    		String text = getBuilderText();
	    		if (text != null) {
	    			map.put(text, currentId);
	    		}
	    		currentId = null;
	    		grabLabel = false;
	    	}
	    }
	    
	    public void characters (char ch[], int start, int length) {
	    	if (grabLabel) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
	
	public class WhiteHatVulnerabilitiesParser extends DefaultHandler {
		
		public Finding finding = new Finding();
		
		private Map<FindingKey, String> map = new EnumMap<>(FindingKey.class);
		
		private boolean creatingVuln = false;
		
		private DateStatus dateStatus = null;
		
		private void addFinding() {
			Finding finding = constructFinding(map);
			
			if (finding == null) {
				log.warn("Finding was null.");
			} else {
				String nativeId = hashFindingInfo(map.get(FindingKey.VULN_CODE), map.get(FindingKey.PATH), map.get(FindingKey.PARAMETER));
				finding.setNativeId(nativeId);
				finding.setDisplayId(map.get(FindingKey.NATIVE_ID));
			}
			
			if (findingDateStatusMap.containsKey(finding)){
				findingDateStatusMap.get(finding).add(dateStatus);
				
			} else {
				findingDateStatusMap.put(finding, Arrays.asList(dateStatus));
			}
		}
		
		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
	    
	    	if ("vulnerabilities".equals(qName)) {
	    		scanDateList = new ArrayList<>();
	    		findingDateStatusMap = new HashMap<>();
	    	}
	    	else if ("vulnerability".equals(qName)) {
	    		map.clear();
	    		map.put(FindingKey.NATIVE_ID, atts.getValue("id"));
	    		map.put(FindingKey.VULN_CODE, atts.getValue("class"));
	    		map.put(FindingKey.SEVERITY_CODE, atts.getValue("severity"));
	    	} else if ("attack_vector".equals(qName)) {
	    		map.put(FindingKey.PATH, null);
	    		map.put(FindingKey.PARAMETER, null);
	    		dateStatus = new DateStatus();
	    		creatingVuln = true;
	    		Calendar testedDate = getCalendarFromString("yyyy-MM-dd", atts.getValue("tested"));
	    		testedDate.set(Calendar.HOUR_OF_DAY, 0);
	    		testedDate.set(Calendar.MINUTE, 0);
	    		testedDate.set(Calendar.SECOND, 0);
	    		testedDate.set(Calendar.MILLISECOND, 0);
	    		
	    		dateStatus.setDate(testedDate);
	    		dateStatus.setStatus(atts.getValue("state"));
	    		if (scanDateList != null && !scanDateList.contains(testedDate))
	    			scanDateList.add(testedDate);
	    	}
	    	else if (creatingVuln) {
	    		if (qName.equals("request")) {
		    		map.put(FindingKey.PATH, getPath(atts.getValue("url")));
		    	} else if (qName.equals("param")) {
		    		map.put(FindingKey.PARAMETER, atts.getValue("name"));
		    	}
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String localName, String qName) throws SAXException {	    	
	    	if (qName.equals("attack_vector")) {
	    		addFinding();
	    		creatingVuln = false;
	    	}
	    }
	    
	    private String getPath(String fullUrl) {
	    	try {
				URL url = new URL(fullUrl);
				return url.getPath();
			} catch (MalformedURLException e) {
				log.warn("Tried to parse a URL out of a url in Attack Vector String but failed.");
			}
	    	return null;
	    }
	}
	
	public class DateStatus implements Comparable<DateStatus> {
		
		private Calendar date;
		private String status;

		public Calendar getDate() {
			return date;
		}

		public void setDate(Calendar date) {
			this.date = date;
		}

		public String getStatus() {
			return status;
		}

		public void setStatus(String status) {
			this.status = status;
		}

		@Override
		public int compareTo(DateStatus other) {
			return this.getDate().compareTo(other.getDate());
		}
		
		
		
	}

	
}
