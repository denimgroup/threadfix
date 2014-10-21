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
package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class WhiteHatRemoteProvider extends RemoteProvider {

	private static final String SITES_URL = "https://sentinel.whitehatsec.com/api/site/";
	private static final String VULNS_URL = "https://sentinel.whitehatsec.com/api/vuln/";
	private static final String EXTRA_PARAMS = "&display_attack_vectors=1&query_site=";
	
	private String apiKey = null;
	
	private List<Calendar> scanDateList = null;
	private Map<Finding, List<DateStatus>> findingDateStatusMap = null;

    RemoteProviderHttpUtils utils = new RemoteProviderHttpUtilsImpl<>(this.getClass());

    public WhiteHatRemoteProvider() {
		super(ScannerType.SENTINEL);
	}

	@Override
	public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
		LOG.info("Retrieving a WhiteHat scan.");

		apiKey = remoteProviderApplication.getRemoteProviderType().getApiKey();

        HttpResponse response = utils.getUrl(SITES_URL + "?key=" + apiKey);

		InputStream labelSiteIdStream;
		if (response.isValid()) {
            labelSiteIdStream = response.getInputStream();
        } else {
			LOG.warn("Received a " + response.getStatus() + " status code from WhiteHat servers while trying " +
                    "to get scans for " + remoteProviderApplication.getNativeName() + ", returning null.");
			return null;
		}
		
		String appName = remoteProviderApplication.getNativeName();
		
		WhiteHatSitesParser parser = new WhiteHatSitesParser();
		
		parse(labelSiteIdStream, parser);
		
		String siteId = parser.map.get(appName);
		if (siteId == null) {
			LOG.warn("No build ID was parsed.");
			return null; // we failed.
		} else {
			LOG.info("Retrieved build ID " + siteId + " for application " + appName);
		}
		
		String url = VULNS_URL + "?key=" + apiKey + EXTRA_PARAMS + siteId;
		
		LOG.info("Requesting site ID " + siteId);

        response = utils.getUrl(url);
        if (response.isValid()) {
            inputStream = response.getInputStream();
        } else {
			LOG.warn("Received a bad response from WhiteHat servers, returning null.");
			return null;
		}

		DefaultHandler scanParser =
                remoteProviderApplication.getRemoteProviderType().getMatchSourceNumbersNullSafe() ?
                        new MatchingParser() :
                        new ThreadFixStyleParser();

		List<Scan> scans = parseSAXInputWhiteHat(scanParser);
		
		if (scans == null || scans.size() == 0) {
			LOG.warn("No scan was parsed, returning null.");
			return null;
		}
		
		for (Scan resultScan : scans) {
			resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
        }
		
		LOG.info("WhiteHat "+ scans.size() +" scans successfully parsed.");
		
		return filterScans(scans);
	}

	/**
	 * This method checks if there are 2 scans with consecutive imported dates and same finding list. If any, remove the earlier one.
	 * @param scans
	 * @return
	 */
	private List<Scan> filterScans(List<Scan> scans) {
		List<Scan> resultList = list();

		for (Scan s: scans) {
			resultList.add(s);
        }

		for (int i = 0; i < scans.size() - 1; i++) {
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
			LOG.warn("Insufficient credentials.");
			return null;
		}
		
		apiKey = remoteProviderType.getApiKey();
		
		WhiteHatSitesParser parser = new WhiteHatSitesParser();

        HttpResponse response = utils.getUrl(SITES_URL + "?key=" + apiKey);

        if (response.isValid()) {
		    parse(response.getInputStream(), parser);
        } else {
            LOG.error("Unable to retrieve applications due to " + response.getStatus() +
                    " response status from WhiteHat servers.");
            return null;
        }

		return parser.getApplications();
	}

	/**
	 * This method parses input file to list of scan
	 * @param handler
	 * @return
	 */
	private List<Scan> parseSAXInputWhiteHat(DefaultHandler handler) {
		LOG.debug("Starting WhiteHat SAX Parsing.");
		
		if (inputStream == null)
			return null;
		
		List<Scan> scanList = list();
		
		ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);
		Collections.sort(scanDateList);
		
		for (Calendar d : scanDateList) {
			date = d;
			saxFindingList = list();
			for (Finding finding : findingDateStatusMap.keySet()) {
				List<DateStatus> dateInfo = findingDateStatusMap.get(finding);
				Collections.sort(dateInfo);
				boolean isAdded = false;

				// Checking if Finding is open at this time
				for (int i=0; i < dateInfo.size() - 1; i++) {
					if (date.compareTo(dateInfo.get(i).getDate()) >= 0 &&
                            date.compareTo(dateInfo.get(i+1).getDate()) < 0) {
						if (dateInfo.get(i).getStatus().equals("open")) {
							saxFindingList.add(finding);
							isAdded = true;
							break;
						}
					}
				}
				if (!isAdded) {
					if (date.compareTo(dateInfo.get(dateInfo.size()-1).getDate()) >= 0
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
			LOG.debug("SAX Parser found the scan date: " + date.getTime().toString());
			scan.setImportTime(date);
		} else {
			LOG.warn("SAX Parser did not find the date.");
		}

		if (scan.getFindings() != null && scan.getFindings().size() != 0)
			LOG.debug("SAX Parsing successfully parsed " + scan.getFindings().size() +" Findings.");
		else
			LOG.warn("SAX Parsing did not find any Findings.");
		
		return scan;
	}

	public class WhiteHatSitesParser extends HandlerWithBuilder {
		
		public Map<String, String> map = new HashMap<>();
		
		private String currentId = null;
		private boolean grabLabel;
		
		public List<RemoteProviderApplication> getApplications() {
			List<RemoteProviderApplication> apps = list();
			for (String label : map.keySet()) {
				RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
	    		remoteProviderApplication.setNativeName(label);
	    		remoteProviderApplication.setNativeId(map.get(label));
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
	
	public class ThreadFixStyleParser extends HandlerWithBuilder {
		
		public Finding finding = new Finding();
		
		private Map<FindingKey, String> map = new EnumMap<>(FindingKey.class);
		
		private boolean creatingVuln = false;
		
		private DateStatus dateStatus = null;

        private String vulnTag = null;
        private boolean inAttackVector = false;
        private StringBuffer currentRawFinding = new StringBuffer();
		
		private void addFinding() {
			Finding finding = constructFinding(map);
			
			if (finding == null) {
				LOG.warn("Finding was null.");
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

        private String buildUrlReference(String siteId, String nativeId) {

            String urlReference = null;

            if (siteId != null && nativeId != null){
                urlReference = ScannerType.SENTINEL.getBaseUrl() +  "?site_id=" + siteId +"&vuln_id=" + nativeId;
            }

            return urlReference;
        }
		
		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
	    
	    	if ("vulnerabilities".equals(qName)) {
	    		scanDateList = list();
	    		findingDateStatusMap = new HashMap<>();
	    	}
	    	else if ("vulnerability".equals(qName)) {
                vulnTag = makeTag(name, qName, atts) + "\n";
	    		map.clear();

                String nativeId = atts.getValue("id");
                String siteId = atts.getValue("site");

                map.put(FindingKey.NATIVE_ID, nativeId);
	    		map.put(FindingKey.VULN_CODE, atts.getValue("class"));
	    		map.put(FindingKey.SEVERITY_CODE, atts.getValue("severity"));
                map.put(FindingKey.URL_REFERENCE, buildUrlReference(siteId, nativeId));
	    	} else if ("attack_vector".equals(qName)) {
                currentRawFinding.append(makeTag(name, qName , atts));
	    		map.put(FindingKey.PATH, null);
	    		map.put(FindingKey.PARAMETER, null);
	    		dateStatus = new DateStatus();
	    		creatingVuln = true;
	    		Calendar testedDate = DateUtils.getCalendarFromString("yyyy-MM-dd", atts.getValue("tested"));
                if (testedDate != null) {
                    testedDate.set(Calendar.HOUR_OF_DAY, 0);
                    testedDate.set(Calendar.MINUTE, 0);
                    testedDate.set(Calendar.SECOND, 0);
                    testedDate.set(Calendar.MILLISECOND, 0);
                }
	    		dateStatus.setDate(testedDate);
	    		dateStatus.setStatus(atts.getValue("state"));
	    		if (scanDateList != null && !scanDateList.contains(testedDate))
	    			scanDateList.add(testedDate);
	    	}
	    	else if (creatingVuln) {
                currentRawFinding.append(makeTag(name, qName , atts));
                if (qName.equals("request")) {
		    		map.put(FindingKey.PATH, getPath(atts.getValue("url")));
		    	} else if (qName.equals("param")) {
		    		map.put(FindingKey.PARAMETER, atts.getValue("name"));
		    	}
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String localName, String qName) throws SAXException {
            if (creatingVuln) {
                currentRawFinding.append("</").append(qName).append(">");
            }

            if (qName.equals("attack_vector")) {
                currentRawFinding.append("\n</").append("vulnerability").append(">");
                map.put(FindingKey.RAWFINDING, vulnTag + currentRawFinding.toString());
	    		addFinding();
	    		creatingVuln = false;
                currentRawFinding.setLength(0);
	    	}

            if ("vulnerability".equals(qName)) {
                vulnTag = null;
            }
	    }
	}

    private String getPath(String fullUrl) {

        String returnPath = "/";

        String urlWithHttp = fullUrl.startsWith("http") ? fullUrl : "http://" + fullUrl;
        try {
            URL url = new URL(urlWithHttp);
            if (url.getPath() != null && !url.getPath().isEmpty()) {
                returnPath = url.getPath();
            }
        } catch (MalformedURLException e) {
            LOG.warn("Tried to parse a URL out of a url in Attack Vector String but failed: " + urlWithHttp);
        }

        return returnPath;
    }

	public class MatchingParser extends HandlerWithBuilder {

		public Finding finding = new Finding();

		private Map<FindingKey, String> map = new EnumMap<>(FindingKey.class);

		private boolean creatingVuln = false;

		private DateStatus dateStatus = null;

        private String vulnTag = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();

		private void addFinding() {
			Finding finding = constructFinding(map);

			if (finding == null) {
				LOG.warn("Finding was null.");
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

        private String buildUrlReference(String siteId, String nativeId) {

            String urlReference = null;

            if (siteId != null && nativeId != null){
                urlReference = ScannerType.SENTINEL.getBaseUrl() +  "?site_id=" + siteId +"&vuln_id=" + nativeId;
            }

            return urlReference;
        }

		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {

	    	if ("vulnerabilities".equals(qName)) {
	    		scanDateList = list();
	    		findingDateStatusMap = new HashMap<>();
	    	}
	    	else if ("vulnerability".equals(qName)) {
                vulnTag = makeTag(name, qName, atts) + "\n";
	    		map.clear();

                String nativeId = atts.getValue("id");
                String siteId = atts.getValue("site");

	    		map.put(FindingKey.NATIVE_ID, nativeId);
	    		map.put(FindingKey.VULN_CODE, atts.getValue("class"));
	    		map.put(FindingKey.SEVERITY_CODE, atts.getValue("severity"));
	    		map.put(FindingKey.URL_REFERENCE, buildUrlReference(siteId, nativeId));

                // was in the attack_vector
	    		map.put(FindingKey.PATH, getPath(atts.getValue("url")));
	    		map.put(FindingKey.PARAMETER, null);
	    		creatingVuln = true;
	    		dateStatus = new DateStatus();
	    		Calendar testedDate = DateUtils.getCalendarFromString("yyyy-MM-dd", atts.getValue("found"));
                if (testedDate != null) {
                    testedDate.set(Calendar.HOUR_OF_DAY, 0);
                    testedDate.set(Calendar.MINUTE, 0);
                    testedDate.set(Calendar.SECOND, 0);
                    testedDate.set(Calendar.MILLISECOND, 0);
                }
	    		dateStatus.setDate(testedDate);
	    		dateStatus.setStatus(atts.getValue("status"));
	    		if (scanDateList != null && !scanDateList.contains(testedDate)) {
                    scanDateList.add(testedDate);
                }
	    	}
	    	else if (creatingVuln) {
                currentRawFinding.append(makeTag(name, qName , atts));
		    	if (qName.equals("param")) {
		    		map.put(FindingKey.PARAMETER, atts.getValue("name"));
		    	}
	    	}
	    }

	    @Override
	    public void endElement (String uri, String localName, String qName) throws SAXException {
            if (creatingVuln) {
                currentRawFinding.append("</").append(qName).append(">");
            }

            if ("vulnerability".equals(qName)) {
                vulnTag = null;

                currentRawFinding.append("\n</").append("vulnerability").append(">");
                map.put(FindingKey.RAWFINDING, vulnTag + currentRawFinding.toString());
                addFinding();
                creatingVuln = false;
                currentRawFinding.setLength(0);
            }
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
