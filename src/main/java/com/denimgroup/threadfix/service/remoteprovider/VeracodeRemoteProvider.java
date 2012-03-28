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
package com.denimgroup.threadfix.service.remoteprovider;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;
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
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;

public class VeracodeRemoteProvider extends RemoteProvider {
	
	private static String GET_APP_BUILDS_URI = "https://analysiscenter.veracode.com/api/2.0/getappbuilds.do";
	private static String GET_DETAILED_REPORT_URI = "https://analysiscenter.veracode.com/api/detailedreport.do";

	private String password = null;
	private String username = null;
	
	@Autowired
	public VeracodeRemoteProvider(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;

		setChannelType(ChannelType.VERACODE);
	}

	@Override
	public Scan getScan(RemoteProviderApplication remoteProviderApplication) {
		
		username = remoteProviderApplication.getRemoteProviderType().getUsername();
		password = remoteProviderApplication.getRemoteProviderType().getPassword();
		
		// This block tries to get the latest build for the app and dies if it fails.
		InputStream appBuildsInputStream = getUrl(GET_APP_BUILDS_URI,username,password);
		String appName = remoteProviderApplication.getNativeId();
		VeracodeApplicationIdMapParser parser = new VeracodeApplicationIdMapParser();
		parse(appBuildsInputStream, parser);
		String buildId = parser.map.get(appName);
		
		if (buildId == null) {
			System.out.println("No build ID was parsed.");
			return null; // we failed.
		} else {
			System.out.println("Retrieved build ID " + buildId + " for application " + appName);
		}

		// This block tries to parse the scan corresponding to the build.
		inputStream = getUrl(GET_DETAILED_REPORT_URI + "?build_id=" + buildId, username, password);

		VeracodeSAXParser scanParser = new VeracodeSAXParser();
		Scan resultScan = parseSAXInput(scanParser);
		resultScan.setImportTime(date);
		resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
		
		return resultScan;
	}

	@Override
	public List<RemoteProviderApplication> fetchApplications() {
		if (remoteProviderType == null || remoteProviderType.getUsername() == null ||
				remoteProviderType.getPassword() == null) {
			log.warn("Insufficient credentials.");
			return null;
		}
		
		password = remoteProviderType.getPassword();
		username = remoteProviderType.getUsername();
		
		InputStream stream = null;
		
		stream = getUrl(GET_APP_BUILDS_URI,username,password);
		
		if (stream == null) {
			return null;
		}
		
		VeracodeApplicationBuildsParser parser = new VeracodeApplicationBuildsParser();
		
		parse(stream, parser);

		try {
			if (stream != null) {
				stream.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return parser.list;
	}
	
	public InputStream getUrl(String urlString, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}

		HttpsURLConnection m_connect;
		try {
			m_connect = (HttpsURLConnection) url.openConnection();

			setupAuthorization(m_connect, username, password);

			InputStream is = m_connect.getInputStream();
			
			return is;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void setupAuthorization(HttpsURLConnection connection,
			String username, String password) {
		String login = username + ":" + password;
		String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
		//String encodedLogin = Base64.encodeBase64String(login.getBytes());
		connection.setRequestProperty("Authorization", "Basic " + encodedLogin);
	}

	public class VeracodeApplicationBuildsParser extends DefaultHandler {
		
		public List<RemoteProviderApplication> list = new ArrayList<RemoteProviderApplication>();

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (qName.equals("application")) {
	    		RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
	    		remoteProviderApplication.setNativeId(atts.getValue("app_name"));
	    		remoteProviderApplication.setRemoteProviderType(remoteProviderType);
	    		list.add(remoteProviderApplication);
	    	}
	    }
	}
	
	public class VeracodeApplicationIdMapParser extends DefaultHandler {
		
		public Map<String, String> map = new HashMap<String, String>();
		public Map<String, Calendar> dateMap = new HashMap<String, Calendar>();
		
		private String currentAppName = null;
		private String currentBuildId = null;
		
	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (qName.equals("application")) {
	    		currentAppName = atts.getValue("app_name");
	    	} else if (currentAppName != null && qName.equals("build")) {
	    		currentBuildId = atts.getValue("build_id");
	    		map.put(currentAppName, atts.getValue("build_id"));
	    	} else if (currentAppName != null && currentBuildId != null 
	    			&& qName.equals("analysis_unit")) {
	    		
	    		String dateString = atts.getValue("published_date");
	    		if (dateString != null && dateString.length() > 5)
	    			dateString = dateString.substring(0,dateString.length() - 5);
	    		
	    		Calendar calendar = getCalendarFromString("yyyy-MM-DD'T'HH:mm:ss", dateString);
	    		if (dateMap.get(currentAppName) == null || dateMap.get(currentAppName).before(calendar)) {
	    			map.put(currentAppName, currentBuildId);
	    			dateMap.put(currentAppName, calendar);
	    		}
	    	}
	    }
	}
	
	public class VeracodeSAXParser extends DefaultHandler {
		
		private boolean inStaticFlaws = true;

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name, String qName, Attributes atts) {	    	
	    	if ("detailedreport".equals(qName)) {
	    		date = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("last_update_time"));
	    		if (date == null)
	    			date = getCalendarFromString("yyyy-MM-dd kk:mm:ss", atts.getValue("generation_date"));
	    	}
	    	
	    	if ("dynamicflaws".equals(qName)) {
	    		inStaticFlaws = false;
	    	}
	    	
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
	    			finding.setNativeId(atts.getValue("issueid"));
	    			
	    			// TODO revise this method of deciding whether the finding is static.	    			
    				finding.setIsStatic(inStaticFlaws);
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

	        		saxFindingList.add(finding);
	    		}
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String localName, String qName) throws SAXException {	    	
	    	if (qName.equals("dynamicflaws")) {
	    		if ("dynamicflaws".equals(qName)) {
		    		inStaticFlaws = true;
		    	}
	    	}
	    }
	}
}
