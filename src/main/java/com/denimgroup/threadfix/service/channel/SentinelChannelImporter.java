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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;

/**
 * 
 * @author mcollins
 *
 */
public class SentinelChannelImporter extends AbstractChannelImporter {
	// TODO put into a more appropriate structure - this isn't really a channel
	// importer.
	
	private String baseUrl;

	private HashMap<String, Integer> paramHash;
	private Map<String, Scan> urlScanMap;

	// this is used to keep track of urls that we find that aren't in use by the
	// application
	private List<String> urlsNotInUse;
	private List<String> urlsInUse;

	private Organization org;
	private Application app;

	protected static final Log log = LogFactory.getLog(SentinelChannelImporter.class);
	
	/**
	 * @param channelTypeDao
	 * @param channelVulnerabilityDao
	 * @param channelSeverityDao
	 * @param vulnerabilityMapLogDao
	 */
	@Autowired
	public SentinelChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;

		urlScanMap = new HashMap<String, Scan>();

		urlsNotInUse = new ArrayList<String>();
		urlsInUse = new ArrayList<String>();

		org = null;
		app = null;

		setChannelType(ChannelType.SENTINEL);
	}
	

	/**
	 * @param documentString
	 * @return
	 */
	private static Document getDocumentFromString(String documentString) {
		if (documentString == null) {
			return null;
		}

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = null;

		try {
			builder = factory.newDocumentBuilder();
			if (builder == null) {
				return null;
			}

			return builder.parse(new InputSource(new StringReader(documentString)));
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Parse sentinel scans for all the applications in an organization
	 * 
	 * @param organization
	 * @return
	 */
	public List<Scan> parseSentinelInput(Organization organization, String apiKey) {
		if (organization == null)
			return null;

		this.org = organization;

		if (channelType == null)
			setChannelType(ChannelType.SENTINEL);

		if (channelType == null)
			return null;

		baseUrl = "https://sentinel.whitehatsec.com";

		Document scanXml = getDocumentFromString(makeRequest(baseUrl + "/api/vuln/?key=" + apiKey));

		getFindingsFromXml(scanXml, apiKey);

		closeInputStream();
		matchScansToApplications(organization);

		List<Scan> scanList = collectScansFromHash();

		return scanList;
	}

	/**
	 * App scan input for a single application
	 * 
	 * @param organization
	 * @return
	 */
	public List<Scan> parseSentinelAppInput(Application application, String apiKey) {
		if (application == null)
			return null;

		this.app = application;

		if (channelType == null)
			setChannelType(ChannelType.SENTINEL);

		if (channelType == null)
			return null;

		baseUrl = "https://sentinel.whitehatsec.com";

		Document scanXml = getDocumentFromString(makeRequest(baseUrl + "/api/vuln/?"
				+ "&key=" + apiKey));

		getFindingsFromXml(scanXml, apiKey);

		closeInputStream();

		matchScansToApplication(application);

		List<Scan> scanList = collectScansFromHash();

		return scanList;
	}

	/**
	 * We need this to conform to the interface but we use a different method to get
	 * vulns from Sentinel.
	 */
	@Override
	public Scan parseInput() {
		return null;
	}

	/**
	 * Pulls the Vulnerabilities (location / vulnerability type pairs) and
	 * passes control off to parseVulnerabilityNode to get findings from those.
	 * 
	 * @param scanXml
	 *            The scan results document, parsed.
	 * @return A list of findings, null on error.
	 */
	private List<Finding> getFindingsFromXml(Document scanXml, String apiKey) {
		if (scanXml == null || apiKey == null)
			return null;

		List<Finding> findings = new LinkedList<Finding>();
		NodeList vulnNodes = scanXml.getElementsByTagName("vulnerability");
		List<Finding> tempFindings = null;

		for (int i = 0; i < vulnNodes.getLength(); i++) {
			Node node = vulnNodes.item(i);
			tempFindings = parseVulnerabilityNode((Element) node, apiKey);
			if (tempFindings != null) {
				findings.addAll(tempFindings);
			}
		}

		return findings;
	}

	/**
	 * Get the file for the Vulnerability and call parseSingleFinding on each
	 * attack_vector.
	 * 
	 * @param vulnNode
	 *            The vuln XML node.
	 * @return A list of findings from the vulnerability node, empty list if
	 *         there aren't any, null on error.
	 */
	private List<Finding> parseVulnerabilityNode(Element vulnNode, String apiKey) {
		if (vulnNode == null) {
			return null;
		}

		String path = vulnNode.getAttribute("url");
		Scan scan = getScanFromPath(path);
		if (scan == null) {
			return null;
		}

		paramHash = new HashMap<String, Integer>();
		ChannelVulnerability cv = getChannelVulnerability(vulnNode.getAttribute("class"));
		ChannelSeverity cs = getChannelSeverity(vulnNode.getAttribute("severity"));

		String url = baseUrl + vulnNode.getAttribute("href") + "?display_attack_vectors=1&key="
				+ apiKey;
		
		Document vulnScan = getDocumentFromString(makeRequest(url));

		if (vulnScan == null) {
			return null;
		}

		NodeList resultNodeList = vulnScan.getElementsByTagName("attack_vector");
		LinkedList<Finding> findings = new LinkedList<Finding>();

		for (int i = 0; i < resultNodeList.getLength(); i++) {
			Finding finding = parseSingleFinding((Element) resultNodeList.item(i), cv);
			if (finding != null) {
				finding.setChannelSeverity(cs);
				findings.addFirst(finding);
			}
		}

		if (scan.getFindings() == null) {
			scan.setFindings(new ArrayList<Finding>());
		}

		updateVulnerabilityTimes(vulnNode, findings);

		for (Finding f : findings) {
			if (f != null) {
				scan.getFindings().add(f);
			}
		}

		return findings;
	}

	/**
	 * Check to see if the organization has an app with the given URL.
	 * 
	 * @param url
	 * @return
	 */
	private boolean urlInUse(String url) {
		if (url == null || org == null || org.getActiveApplications() == null
				|| org.getActiveApplications().size() == 0) {
			return false;
		}

		if (urlsNotInUse.contains(url)) {
			return false;
		}

		if (urlsInUse.contains(url)) {
			return true;
		}

		for (Application app : org.getActiveApplications()) {
			if (app != null) {
				String appUrl = app.getUrl();
				String truncatedAppUrl = appUrl.substring(appUrl.indexOf("//") + 2);
				if (appUrl.equals(url) || truncatedAppUrl.equals(url)) {
					urlsInUse.add(url);
					return true;
				}
			}
		}

		urlsNotInUse.add(url);
		return false;
	}

	/**
	 * Parses the information from a single finding entry.
	 * 
	 * @param path
	 * @param attackVectorElement
	 * @param cv
	 * @return A single finding object.
	 */
	private Finding parseSingleFinding(Element attackVectorElement, ChannelVulnerability cv) {
		if (attackVectorElement == null || cv == null) {
			return null;
		}

		String url = getUrlFromAttackVector(attackVectorElement);
		String param = getParamFromAttackVector(attackVectorElement);
		
		if (url == null && param == null)
			return null;
		
		if (param != null && paramHash.containsKey(param)) {
			return null;
		} else {
			paramHash.put(param, 1);
		}

		Finding finding = new Finding();
		finding.setNativeId(attackVectorElement.getAttribute("id"));
		finding.setChannelVulnerability(cv);
		finding.setSurfaceLocation(getSurfaceLocation(url, param));
		finding.setIsStatic(false);

		return finding;
	}

	/**
	 * @param attackVectorElement
	 * @return
	 */
	private String getUrlFromAttackVector(Element attackVectorElement) {
		if (attackVectorElement == null) {
			return null;
		}

		Element requestElement = (Element) attackVectorElement.getFirstChild();
		if (requestElement == null) {
			return null;
		}

		String url = requestElement.getAttribute("url");
		if (url == null || url.trim().equals("")) {
			return null;
		} else {
			url = url.substring(url.indexOf('/') + 1);
			url = url.substring(url.indexOf('/') + 1);
			url = url.substring(url.indexOf('/'));
			if (url.indexOf('?') > 0)
				url = url.substring(0, url.indexOf('?'));
			return url;
		}
	}

	/**
	 * @param attackVectorElement
	 * @return
	 */
	private String getParamFromAttackVector(Element attackVectorElement) {
		if (attackVectorElement == null) {
			return null;
		}

		Element paramElement = (Element) attackVectorElement.getFirstChild().getFirstChild();
		if (paramElement == null) {
			return null;
		}

		String param = paramElement.getAttribute("name");
		if (param == null || param.trim().equals(""))
			return null;

		return param;
	}

	/**
	 * @param path
	 * @param param
	 * @return
	 */
	private SurfaceLocation getSurfaceLocation(String path, String param) {
		// It doesn't matter if one or both parameters are null
		SurfaceLocation location = new SurfaceLocation();

		if (path != null) {
			location.setPath(path);
			int index = path.indexOf(':');
			if (index > 0 && index < path.length()) {
				location.setProtocol(path.substring(0, index));
			}
		}

		location.setParameter(param);
		return location;
	}

	/**
	 * @param dateString
	 * @return
	 */
	private Calendar getDateFromString(String dateString) {
		// This function works if the date is in the 2007-01-11T18:00:10Z format
		if (dateString == null || dateString.trim().equals(""))
			return null;

		dateString = dateString.replace("T", " ").replace("Z", "");
		return getCalendarFromString("yyyy-mm-dd kk:mm:ss", dateString);
	}

	/**
	 * @param organization
	 */
	private void matchScansToApplications(Organization organization) {
		if (urlScanMap == null || organization == null || 
				organization.getActiveApplications() == null || 
				organization.getActiveApplications().size() == 0)
			return;

		for (Application app : organization.getActiveApplications())
			matchScansToApplication(app);
	}

	/**
	 * @param application
	 */
	private void matchScansToApplication(Application app) {
		if (urlScanMap == null)
			return;

		String url = app.getUrl();
		Scan scan = null;

		if (url != null && !url.trim().equals("") && urlScanMap.containsKey(url)
				&& urlScanMap.get(url) != null)
			scan = urlScanMap.get(url);

		String truncatedUrl = null;
		if (url != null)
			truncatedUrl = url.substring(url.indexOf("//") + 2);
		if (truncatedUrl != null && !truncatedUrl.trim().equals("")
				&& urlScanMap.containsKey(truncatedUrl) && urlScanMap.get(truncatedUrl) != null) {
			scan = urlScanMap.get(truncatedUrl);
		}
		
		if (app.getScans() == null) {
			app.setScans(new ArrayList<Scan>());
		}
		
		if (scan != null) {
			scan.setApplication(app);
			ApplicationChannel applicationChannel = getOrCreateApplicationChannel(app);
			scan.setApplicationChannel(applicationChannel);
			applicationChannel.getScanList().add(scan);
			app.getScans().add(scan);
		}
	}

	/**
	 * @return
	 */
	private List<Scan> collectScansFromHash() {
		if (urlScanMap == null) {
			return null;
		}

		List<Scan> scanList = new ArrayList<Scan>();
		for (String key : urlScanMap.keySet()) {
			if (urlScanMap.get(key) != null) {
				scanList.add(urlScanMap.get(key));
			}
		}
		
		if (scanList.size() == 0)
			return null;
		else
			return scanList;
	}

	/**
	 * @param vulnNode
	 * @param findings
	 */
	private void updateVulnerabilityTimes(Node vulnNode, List<Finding> findings) {
		if (vulnNode == null || findings == null || findings.size() == 0) {
			return;
		}

		Element element = (Element) vulnNode;
		Calendar openedDate = getDateFromString(element.getAttribute("opened"));
		Calendar closedDate = getDateFromString(element.getAttribute("closed"));
		boolean open = (closedDate == null);

		for (Finding finding : findings) {
			if (finding != null && finding.getVulnerability() != null) {
				finding.getVulnerability().setCloseTime(closedDate);
				finding.getVulnerability().setActive(open);
				finding.getVulnerability().setOpenTime(openedDate);
			}
		}
	}

	/**
	 * @param path
	 * @return
	 */
	private Scan getScanFromPath(String path) {
		if (path != null && !path.trim().equals("")) {
			String key = path;
			if (key.contains("/")) {
				key = key.substring(0, key.indexOf('/'));
			}

			if (org == null && app != null && app.isActive()) {
				if (!key.equals(app.getUrl()) && !key.equals(app.getUrl().substring(7)))
					return null;

				if (!urlScanMap.containsKey(key)) {
					urlScanMap.put(key, new Scan());
				}
			}

			if (app == null && org != null && org.getActiveApplications() != null
					&& org.getActiveApplications().size() != 0) {
				if (!urlInUse(key)) {
					return null;
				}

				if (!urlScanMap.containsKey(key)) {
					urlScanMap.put(key, new Scan());
				}
			}

			return urlScanMap.get(key);
		} else {
			return null;
		}
	}

	/**
	 * @param urlStr
	 * @return
	 */
	public static String makeRequest(String urlStr) {
		URL url = null;
		String result = null;

		try {
			url = new URL(urlStr);

			log.debug("Sending request to " + urlStr);

			URLConnection conn = url.openConnection();
			conn.setReadTimeout(60000); // milliseconds

			// Get the response
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			StringBuffer sb = new StringBuffer();

			String line = null;
			while ((line = rd.readLine()) != null) {
				sb.append(line);
			}

			rd.close();
			result = sb.toString();

			log.debug("Got a response");
		} catch (IOException e) {
			log.warn("Didn't get a response from Sentinel servers, ensure that the URL is correct.", e);
		}

		return result;
	}

	/**
	 * Get existing sites from sentinel server with given api key
	 * 
	 * @param key
	 * @return
	 */
	public static List<String> getSites(String key) {
		String base = "https://sentinel.whitehatsec.com";
		String wholeUrl = base + "/api/sites/?" + "&key=" + key;
		
		Document siteXml = getDocumentFromString(makeRequest(wholeUrl));
		if (siteXml == null)
			return null;
		else
			return getSitesFromXml(siteXml);
	}

	/**
	 * Parse the sites xml file to get a site list
	 * 
	 * @param siteXml
	 * @return
	 */
	public static List<String> getSitesFromXml(Document siteXml) {
		if (siteXml == null)
			return null;

		List<String> sites = new ArrayList<String>();
		NodeList siteNodes = siteXml.getElementsByTagName("site");

		for (int i = 0; i < siteNodes.getLength(); i++) {
			Node node = siteNodes.item(i);
			sites.add(node.getTextContent());
		}

		return sites;
	}

	private ApplicationChannel getOrCreateApplicationChannel(Application application) {
		if (application == null)
			return null;
		
		if (application.getChannelList() == null)
			application.setChannelList(new ArrayList<ApplicationChannel>());
		
		for (ApplicationChannel appChannel : application.getChannelList()) {
			if (appChannel != null && appChannel.getChannelType() != null
					&& appChannel.getChannelType().getName() != null
				    && appChannel.getChannelType().getName().equals(ChannelType.SENTINEL)) {
				if (appChannel.getScanList() == null)
					appChannel.setScanList(new ArrayList<Scan>());
				
				return appChannel;
			}
		}
		
		ApplicationChannel newApplicationChannel = new ApplicationChannel();
		newApplicationChannel.setApplication(application);
		newApplicationChannel.setChannelType(channelTypeDao.retrieveByName(ChannelType.SENTINEL));
		newApplicationChannel.setScanList(new ArrayList<Scan>());
		application.getChannelList().add(newApplicationChannel);
		return newApplicationChannel;
	}


	@Override
	public String checkFile() {
		return ChannelImporter.WRONG_FORMAT_ERROR;
	}	
}
