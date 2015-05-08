////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringEscapeUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;

@RemoteProvider(name = "WhiteHat Sentinel Source")
public class WhiteHatSourceRemoteProvider extends AbstractRemoteProvider {

	private static final String APPLICATIONS_URL = "https://sentinel.whitehatsec.com/api/application/";
	private static final String EXTRA_PARAMS_OPEN = "&display_steps=1&query_status=open",
			EXTRA_PARAMS_CLOSED = "&display_steps=1&query_status=closed";
	private static final int PAGE_LIMIT = 1000;
	private static final String API_KEY = "API Key", OPEN_STATUS = "open", CLOSED_STATUS = "closed";
	private static final String TAB_SPACE = "\t";

	private String apiKey = null;

	private List<Calendar> scanDateList = list();
	private Map<String, FindingStatus> findingStatusMap = map();



	RemoteProviderHttpUtils utils = getImpl(this.getClass());

	public WhiteHatSourceRemoteProvider() {
		super(ScannerType.SENTINEL_SOURCE);
	}

	@Override
	public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
		LOG.info("Retrieving a WhiteHat Source scan.");

		apiKey = getAuthenticationFieldValue(API_KEY);

		String appName = remoteProviderApplication.getNativeName();
		String siteId = remoteProviderApplication.getNativeId();
		if (siteId == null) {
			LOG.warn("No build ID was parsed.");
			return null; // we failed.
		} else {
			LOG.info("Retrieved build ID " + siteId + " for application " + appName);
		}

		saxFindingList = list();

		String url = APPLICATIONS_URL + siteId + "/vuln/?key=" + apiKey + EXTRA_PARAMS_OPEN;
		LOG.info("Requesting open findings from site ID " + siteId);
		getFindingsFromUrl(url);
		LOG.info("Got " + saxFindingList.size() + " open findings from site ID " + siteId);

		url = APPLICATIONS_URL + siteId + "/vuln/?key=" + apiKey + EXTRA_PARAMS_CLOSED;
		LOG.info("Requesting closed findings from site ID " + siteId);
		getFindingsFromUrl(url);
		LOG.info("Got " + saxFindingList.size() + " open and closed findings from site ID " + siteId);

		List<Scan> scanList = list();
		Collections.sort(scanDateList);
		List<Finding> newScanFindings;

		for (Calendar d : scanDateList) {
			date = d;
			newScanFindings = list();
			for (Finding finding: saxFindingList) {
				if (findingStatusMap.containsKey(finding.getNativeId())) {
					FindingStatus findingStatus = findingStatusMap.get(finding.getNativeId());
					if (d.compareTo(findingStatus.getOpenedDate()) >= 0) {

						// Checking if Finding is open at this time
						if (OPEN_STATUS.equals(findingStatus.getStatus())){
							newScanFindings.add(finding);
						} else if (findingStatus.getClosedDate() != null && findingStatus.getClosedDate().after(d)) {
							newScanFindings.add(finding);
						}
					}
				}
			}


			scanList.add(makeNewScan(newScanFindings));
		}

		if (scanList == null || scanList.size() == 0) {
			LOG.error("No scan was parsed, something is broken.");
			return null;
		}

		LOG.info("WhiteHat "+ " scans successfully parsed.");

		return filterScans(scanList);
	}

	/**
	 * Get all open or closed findings and save them into saxFindingList
	 * @param url
	 */
	private void getFindingsFromUrl(String url) {
		HttpResponse response = utils.getUrl(url);
		if (response.isValid()) {
			inputStream = response.getInputStream();
		} else {
			LOG.warn("Received a bad response from WhiteHat servers, returning null.");
			return;
		}

		parseSAXInputWhiteHat(new WhiteHatSourceParser());
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

		apiKey = getAuthenticationFieldValue(API_KEY);

		if (remoteProviderType == null || apiKey == null) {
			LOG.warn("Insufficient credentials.");
			return null;
		}

		WhiteHatAppsParser parser = getParserWithAllApps();
		if (parser == null) {
			return null;
		}

		return parser.getApplications();
	}

	private WhiteHatAppsParser getParserWithAllApps() {
		int pageOffset = 0;
		String paginationSettings = "&page:limit=" + PAGE_LIMIT + "&page:offset=" + pageOffset;

		WhiteHatAppsParser parser = new WhiteHatAppsParser();

		HttpResponse response = utils.getUrl(APPLICATIONS_URL + "?key=" + apiKey + paginationSettings);

		if (response.isValid()) {
			parse(response.getInputStream(), parser);
		} else {
			LOG.error("Unable to retrieve applications due to " + response.getStatus() +
					" response status from WhiteHat servers.");
			return null;
		}

		int totalSitesAvailable = parser.getTotalSites();

		while (parser.getApplications().size() < totalSitesAvailable) {
			pageOffset += PAGE_LIMIT;
			paginationSettings = "&page:limit=" + PAGE_LIMIT + "&page:offset=" + pageOffset;

			response = utils.getUrl(APPLICATIONS_URL + "?key=" + apiKey + paginationSettings);

			if (response.isValid()) {
				parse(response.getInputStream(), parser);
			} else {
				LOG.error("Unable to retrieve applications due to " + response.getStatus() +
						" response status from WhiteHat servers.");
				return null;
			}
		}
		return parser;
	}

	/**
	 * This method parses input file to list of scan
	 * @param handler
	 * @return
	 */
	private void parseSAXInputWhiteHat(DefaultHandler handler) {
		LOG.debug("Starting WhiteHat SAX Parsing.");

		if (inputStream == null)
			return;

		ScanUtils.readSAXInput(handler, "Done Parsing.", inputStream);
	}

	private Scan makeNewScan(List<Finding> newScanFindings) {
		Scan scan = new Scan();
		scan.setFindings(newScanFindings);
		scan.setApplicationChannel(applicationChannel);

		if (date != null) {
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

	public class WhiteHatAppsParser extends HandlerWithBuilder {

		public Map<String, String> idMap = map();

		private String currentId = null;
		private String currentLabel;

		private String totalSites = null;

		public List<RemoteProviderApplication> getApplications() {
			List<RemoteProviderApplication> apps = list();
			for (String label : idMap.keySet()) {
				RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
				remoteProviderApplication.setNativeName(label);
				remoteProviderApplication.setNativeId(idMap.get(label));
				remoteProviderApplication.setRemoteProviderType(remoteProviderType);
				apps.add(remoteProviderApplication);
			}
			return apps;
		}

		public int getTotalSites() {
			int total = 0;
			if (totalSites != null) {
				try {
					total = Integer.valueOf(totalSites);
				} catch (NumberFormatException e) {
					total = 0;
				}
			}
			return total;
		}

		public void startElement(String uri, String name, String qName, Attributes atts) throws SAXException {
			if ("application".equals(qName)) {
				currentId = atts.getValue("id");
				currentLabel = atts.getValue("label");
				idMap.put(currentLabel, currentId);

				currentId = null;
				currentLabel = null;
			} else if ("page".equals(qName)) {
				totalSites = atts.getValue("total");
			}
		}
	}

	public class WhiteHatSourceParser extends HandlerWithBuilder {

		public Finding finding = new Finding();

		private Map<FindingKey, String> map = enumMap(FindingKey.class);

		private boolean creatingVuln = false;

		private String currentFileName, traceId;

		private StringBuffer vulnTag = new StringBuffer();
		private StringBuffer currentRawFinding = new StringBuffer();

		private List<DataFlowElement> currentDataFlowElements = list();

		String nativeId, appId, status;
		Calendar openedDate, closedDate;

		private void addFinding() {
			Finding finding = constructFinding(map);

			if (finding == null) {
				LOG.warn("Finding was null.");
			} else {
				finding.setNativeId(traceId);
				finding.setIsStatic(true);
				finding.setDataFlowElements(currentDataFlowElements);
				saxFindingList.add(finding);
			}
			traceId = null;
			creatingVuln = false;
			currentRawFinding.setLength(0);
			currentDataFlowElements = list();

		}

		private String buildUrlReference(String siteId, String nativeId, String status) {

			String urlReference = null;

			if (siteId != null && nativeId != null){
				urlReference = ScannerType.SENTINEL_SOURCE.getBaseUrl() +  "?app_id=" + siteId +"&vuln_id=" + nativeId + "&status=" + status + "#elements";
			}

			return urlReference;
		}

		public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {

			if ("source_vulns".equals(qName)) {

			} else if ("source_vuln".equals(qName)) {
				vulnTag.append(makeTag(name, qName, atts) + "\n");
				map.clear();

				nativeId = atts.getValue("id");
				appId = atts.getValue("application_id");
				status = atts.getValue("status");
				currentFileName = atts.getValue("location");

				map.put(FindingKey.VULN_CODE, atts.getIndex("class_readable") != -1 ? atts.getValue("class_readable") : atts.getValue("class"));
				map.put(FindingKey.SEVERITY_CODE, atts.getValue("risk"));
				map.put(FindingKey.URL_REFERENCE, buildUrlReference(appId, nativeId, status));
				map.put(FindingKey.PATH, currentFileName);
				map.put(FindingKey.SOURCE_FILE_NAME, currentFileName);
				map.put(FindingKey.PARAMETER, null);

				openedDate  = getCalendarAtMidnight(atts.getValue("opened"));
				closedDate  = getCalendarAtMidnight(atts.getValue("closed"));

				if (!scanDateList.contains(openedDate)) {
					scanDateList.add(openedDate);
				}
				if (closedDate != null && !scanDateList.contains(openedDate))
					scanDateList.add(closedDate);

			} else if ("trace".equals(qName)) {
				creatingVuln = true;
				currentRawFinding.append(makeTag(name, qName , atts));

				traceId = nativeId + "-" + atts.getValue("id");
				map.put(FindingKey.NATIVE_ID, traceId);
				findingStatusMap.put(traceId, new FindingStatus(status, openedDate, closedDate));

			} else if (creatingVuln) {
				currentRawFinding.append("\n" + makeTag(name, qName , atts));
				if (qName.equals("step")) {
					DataFlowElement element = new DataFlowElement();
					Integer lineNo = IntegerUtils.getPrimitive(atts.getValue("relative_line_number"))
							+ IntegerUtils.getPrimitive(atts.getValue("start_line_number"));
					element.setLineNumber(lineNo);
					element.setLineText(StringEscapeUtils.unescapeXml(getLineText(atts.getValue("code"), IntegerUtils.getPrimitive(atts.getValue("relative_line_number")))));
					element.setSourceFileName(atts.getValue("filename"));
					element.setSequence(IntegerUtils.getPrimitive(atts.getValue("id")));
					currentDataFlowElements.add(element);
				}
			} else {
				vulnTag.append("\n" + makeTag(name, qName , atts) + "\n");
			}
		}

		@Override
		public void endElement (String uri, String localName, String qName) throws SAXException {
			if (creatingVuln) {
				currentRawFinding.append("</").append(qName).append(">");
			} else {
				vulnTag.append(makeEndTag(null,qName) + "\n");
			}

			if (qName.equals("trace")) {
				currentRawFinding.append("\n" + makeEndTag(null, "traces"));
				currentRawFinding.append("\n" + makeEndTag(null, "source_vuln"));
				map.put(FindingKey.RAWFINDING, vulnTag.toString() + currentRawFinding.toString());
				addFinding();

			}

			if ("source_vuln".equals(qName)) {
				vulnTag.setLength(0);
			}
		}
	}

	private String getLineText(String code, Integer lineNo) {
		String codeEscaped = new String(Base64.decodeBase64(code.getBytes()));
		String[] lines = codeEscaped.split("\n");
		return lines.length<lineNo + 1 ? null : lines[lineNo].trim();

	}

	private Calendar getCalendarAtMidnight(String found) {
		Calendar testedDate = DateUtils.getCalendarFromString("yyyy-MM-dd", found);
		if (testedDate != null) {
			testedDate.set(Calendar.HOUR_OF_DAY, 0);
			testedDate.set(Calendar.MINUTE, 0);
			testedDate.set(Calendar.SECOND, 0);
			testedDate.set(Calendar.MILLISECOND, 0);
		}
		return testedDate;
	}

	private class FindingStatus {
		private String status;
		private Calendar openedDate, closedDate;

		public FindingStatus(String status, Calendar openedDate, Calendar closedDate) {
			this.status = status;
			this.openedDate = openedDate;
			this.closedDate = closedDate;
		}

		public String getStatus() {
			return status;
		}

		public Calendar getOpenedDate() {
			return openedDate;
		}

		public Calendar getClosedDate() {
			return closedDate;
		}
	}



}
