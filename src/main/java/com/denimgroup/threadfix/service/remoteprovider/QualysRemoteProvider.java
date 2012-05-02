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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.springframework.beans.factory.annotation.Autowired;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * TODO use POST data to pre-filter web requests
 * @author mcollins
 *
 */
public class QualysRemoteProvider extends RemoteProvider {
	
	private String username = null;
	private String password = null;
	
	private static final String GET_SCANS_FOR_APP_URL = "https://qualysapi.qualys.com/qps/rest/3.0/search/was/wasscan";
	private static final String GET_SCAN_URL = "https://qualysapi.qualys.com/qps/rest/3.0/download/was/wasscan/";
	private static final String GET_APPS_URL = "https://qualysapi.qualys.com/qps/rest/3.0/search/was/webapp";
	
	private static Map<String, String> SEVERITIES_MAP = new HashMap<String, String>();
	static {
		SEVERITIES_MAP.put("150000", "5");
		SEVERITIES_MAP.put("150001", "5");
		SEVERITIES_MAP.put("150002", "5");
		SEVERITIES_MAP.put("150003", "5");
		SEVERITIES_MAP.put("150004", "2");
		SEVERITIES_MAP.put("150005", "2");
		SEVERITIES_MAP.put("150006", "1");
		SEVERITIES_MAP.put("150007", "1");
		SEVERITIES_MAP.put("150008", "1");
		SEVERITIES_MAP.put("150009", "1");
		SEVERITIES_MAP.put("150010", "1");
		SEVERITIES_MAP.put("150011", "3");
		SEVERITIES_MAP.put("150012", "5");
		SEVERITIES_MAP.put("150013", "5");
		SEVERITIES_MAP.put("150014", "1");
		SEVERITIES_MAP.put("150015", "1");
		SEVERITIES_MAP.put("150016", "2");
		SEVERITIES_MAP.put("150017", "1");
		SEVERITIES_MAP.put("150018", "2");
		SEVERITIES_MAP.put("150019", "2");
		SEVERITIES_MAP.put("150020", "1");
		SEVERITIES_MAP.put("150021", "1");
		SEVERITIES_MAP.put("150022", "3");
		SEVERITIES_MAP.put("150023", "2");
		SEVERITIES_MAP.put("150024", "1");
		SEVERITIES_MAP.put("150025", "1");
		SEVERITIES_MAP.put("150026", "1");
		SEVERITIES_MAP.put("150028", "1");
		SEVERITIES_MAP.put("150029", "1");
		SEVERITIES_MAP.put("150030", "1");
		SEVERITIES_MAP.put("150032", "3");
		SEVERITIES_MAP.put("150033", "3");
		SEVERITIES_MAP.put("150034", "3");
		SEVERITIES_MAP.put("150035", "1");
		SEVERITIES_MAP.put("150036", "1");
		SEVERITIES_MAP.put("150037", "1");
		SEVERITIES_MAP.put("150038", "1");
		SEVERITIES_MAP.put("150039", "1");
		SEVERITIES_MAP.put("150040", "1");
		SEVERITIES_MAP.put("150041", "1");
		SEVERITIES_MAP.put("150042", "3");
		SEVERITIES_MAP.put("150043", "1");
		SEVERITIES_MAP.put("150044", "3");
		SEVERITIES_MAP.put("150045", "3");
		SEVERITIES_MAP.put("150046", "5");
		SEVERITIES_MAP.put("150047", "5");
		SEVERITIES_MAP.put("150048", "5");
		SEVERITIES_MAP.put("150049", "4");
		SEVERITIES_MAP.put("150051", "3");
		SEVERITIES_MAP.put("150054", "1");
		SEVERITIES_MAP.put("150055", "5");
		SEVERITIES_MAP.put("150057", "5");
		SEVERITIES_MAP.put("150058", "1");
		SEVERITIES_MAP.put("150060", "5");
		SEVERITIES_MAP.put("150061", "1");
		SEVERITIES_MAP.put("150062", "5");
		SEVERITIES_MAP.put("150063", "5");
		SEVERITIES_MAP.put("150064", "1");
		SEVERITIES_MAP.put("150065", "2");
		SEVERITIES_MAP.put("150066", "1");
		SEVERITIES_MAP.put("150067", "3");
		SEVERITIES_MAP.put("150071", "3");
		SEVERITIES_MAP.put("150076", "4");
		SEVERITIES_MAP.put("150077", "1");
		SEVERITIES_MAP.put("150078", "1");
		SEVERITIES_MAP.put("150079", "3");
		SEVERITIES_MAP.put("150081", "1");
		SEVERITIES_MAP.put("150082", "1");
		SEVERITIES_MAP.put("150083", "1");
		SEVERITIES_MAP.put("150084", "1");
		SEVERITIES_MAP.put("150085", "3");
		SEVERITIES_MAP.put("150086", "3");
		SEVERITIES_MAP.put("150087", "1");
		SEVERITIES_MAP.put("150088", "1");
		SEVERITIES_MAP.put("150089", "3");
		SEVERITIES_MAP.put("150090", "5");
		SEVERITIES_MAP.put("150092", "5");
		SEVERITIES_MAP.put("150093", "5");
		SEVERITIES_MAP.put("150094", "1");
		SEVERITIES_MAP.put("150095", "1");
	}
	
	@Autowired
	public QualysRemoteProvider(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao, ChannelSeverityDao channelSeverityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao) {
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;

		setChannelType(ChannelType.QUALYSGUARD_WAS);
	}

	@Override
	public Scan getScan(RemoteProviderApplication remoteProviderApplication) {
		if (remoteProviderApplication.getRemoteProviderType() == null) {
			return null;
		}
		
		password = remoteProviderApplication.getRemoteProviderType().getPassword();
		username = remoteProviderApplication.getRemoteProviderType().getUsername();
		
		String appId = mostRecentScanForApp(remoteProviderApplication);
		
		if (appId == null || appId.trim().equals("")) {
			return null;
		}
				
		inputStream = httpGet(GET_SCAN_URL + appId);

		QualysWASSAXParser scanParser = new QualysWASSAXParser();
		Scan resultScan = parseSAXInput(scanParser);
		
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
		
		// POST with no parameters
		// TODO include filters
		stream = httpPost(GET_APPS_URL,new String[]{},new String[]{});
		
		if (stream == null) {
			return null;
		}
		
		QualysAppsParser parser = new QualysAppsParser();
		
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
	
	// TODO improve this algorithm and check for cases where Qualys has more than one app
	// TODO import all the unimported scans for the app instead of just the most recent
	public String mostRecentScanForApp(RemoteProviderApplication app) {
		if (app == null || app.getNativeId() == null) {
			return null;
		}

		// POST with no parameters
		// TODO include filters
		InputStream stream = httpPost(GET_SCANS_FOR_APP_URL,new String[]{},new String[]{});
		
		QualysScansForAppParser parser = new QualysScansForAppParser();
		parse(stream, parser);
		
		String scan = null;
		Calendar previousDate = null;

		// This should be replaced with the filtered code
		for (Map<String, String> map : parser.list) {
			Calendar mapDate = null;
			
			if (map.get("launchedDate") != null) {
				mapDate = getCalendarFromString("yyyy-MM-DD'T'HH:mm:ss'Z'", map.get("launchedDate"));
			}
			
			if (app.getNativeId().equals(map.get("webAppName")) &&
					(previousDate == null || 
						previousDate.before(mapDate))) {
				scan = map.get("id");
				previousDate = mapDate;
			}
		}
		
		log.info("Returning scan ID " + scan + " for application " + app.getNativeId());

		return scan;
	}
	
	// UTILITIES
	
	private InputStream httpPost(String request, String[] paramNames,
			String[] paramVals) {

		PostMethod post = new PostMethod(request);
		
		post.setRequestHeader("Content-type", "text/xml; charset=UTF-8");

		if (username != null && password != null) {
			String login = username + ":" + password;
			String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
			
			post.setRequestHeader("Authorization", "Basic " + encodedLogin);
		}
				
		try {
			for (int i = 0; i < paramNames.length; i++) {
				post.addParameter(paramNames[i], paramVals[i]);
			}
			
			HttpClient client = new HttpClient();
			int status = client.executeMethod(post);
			if (status != 200) {
				log.warn("Status was not 200.");
				log.warn("Status : " + status);
			}
			
			InputStream responseStream = post.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return responseStream;
			}

		} catch (FileNotFoundException e1) {
			e1.printStackTrace();
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		log.warn("There was an error and the POST request was not finished.");
		return null;
	}
	
	private InputStream httpGet(String urlStr) {
		GetMethod get = new GetMethod(urlStr);
		
		get.setRequestHeader("Content-type", "text/xml; charset=UTF-8");

		if (username != null && password != null) {
			String login = username + ":" + password;
			String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
			
			get.setRequestHeader("Authorization", "Basic " + encodedLogin);
		}
		
		HttpClient client = new HttpClient();
		try {
			int status = client.executeMethod(get);
			if (status != 200) {
				log.warn("Status was not 200.");
				log.warn("Status : " + status);
			}
			
			InputStream responseStream = get.getResponseBodyAsStream();
			
			if (responseStream != null) {
				return responseStream;
			}
		} catch (HttpException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	// PARSER CLASSES

	private class QualysAppsParser extends DefaultHandler {
		
		public List<RemoteProviderApplication> list = new ArrayList<RemoteProviderApplication>();
		
		private boolean getName = false;

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (qName.equals("name")) {
	    		getName = true;
	    	}
	    }

		public void characters (char ch[], int start, int length) {
	    	if (getName) {
	    		String tempNameString = getText(ch,start,length);
	    		
	    		RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
	    		remoteProviderApplication.setNativeId(tempNameString);
	    		remoteProviderApplication.setRemoteProviderType(remoteProviderType);
	    		list.add(remoteProviderApplication);
	    		
	    		getName = false;
	    	}
	    }
	}
	
	private class QualysScansForAppParser extends DefaultHandler {
		
		public List<Map<String,String>> list = new ArrayList<Map<String,String>>();
		
		private boolean inWebApp = false;
		private boolean getName = false;
		private String webAppName = "";
		
		private boolean getId = false;
		private String currentId = null;
		
		private boolean getStatus = false;
		private String currentStatus = null;
		
		private boolean getDate = false;
		private String currentDate = null;

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
	    
	    	if (qName.equals("webApp")) {
	    		inWebApp = true;
	    	} else if (currentId == null && qName.equals("id")) {
	    		getId = true;
	    	} else if (inWebApp && qName.equals("name")) {
	    		getName = true;
	    		inWebApp = false;
	    	} else if (qName.equals("status")) {
	    		getStatus = true;
	    	} else if (qName.equals("launchedDate")) {
	    		getDate = true;
	    	}
	    }
	    
	    @Override
	    public void endElement (String uri, String localName, String qName) throws SAXException {	    	
	    	if (qName.equals("WasScan")) {
	    		Map<String, String> map = new HashMap<String, String>();
	    		map.put("id", currentId);
	    		map.put("status", currentStatus);
	    		map.put("date", currentDate);
	    		map.put("webAppName", webAppName);
	    		
	    		list.add(map);
	    			    		
	    		currentStatus = null;
	    		currentId = null;
	    		currentDate = null;
	    		webAppName = null;
	    	}
	    }

		public void characters (char ch[], int start, int length) {
	    	if (getId) {
	    		currentId = getText(ch,start,length);
	    		getId = false;
	    	} else if (getStatus) {
	    		currentStatus = getText(ch,start,length);
	    		getStatus = false;
	    	} else if (getDate) {
	    		currentDate = getText(ch,start,length);
	    		getDate = false;
	    	} else if (getName) {
	    		String toAdd = getText(ch,start,length);
	    			    		
	    		webAppName = toAdd;
	    		
	    		getName = false;
		    }
	    }
	}
	
	private class QualysWASSAXParser extends DefaultHandler {
		private Boolean getDate               = false;
		private Boolean getUri                = false;
		private Boolean getParameter          = false;
		private Boolean getChannelVulnName    = false;
	
		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
					    
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
	    	if ("launchedDate".equals(qName)) {
	    		getDate = true;
	    	} else if ("uri".equals(qName)) {
	    		getUri = true;
	    	} else if ("qid".equals(qName)) {
	    		getChannelVulnName = true;
	    	} else if ("param".equals(qName)) {
	    		getParameter = true;
	    	} else if ("instances".equals(qName)) {
	    		currentSeverityCode = SEVERITIES_MAP.get(currentChannelVulnCode);
	    		
	    		Finding finding = constructFinding(currentPath, currentParameter, 
	    				currentChannelVulnCode, currentSeverityCode);
	    		add(finding);
	    	
	    		currentParameter       = null;
	    		currentPath            = null;
	    		getParameter           = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		String tempDateString = getText(ch,start,length);

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = getCalendarFromString("yyyy-MM-DD'T'HH:mm:ss'Z'", tempDateString);
	    		}
	    		getDate = false;
	    	} else if (getUri) {
	    		currentPath = getText(ch,start,length);
	    		getUri = false;
	    	} else if (getChannelVulnName) {
	    		currentChannelVulnCode = getText(ch,start,length);
	    		getChannelVulnName = false;
	    	} else if (getParameter) {
	    		currentParameter = getText(ch,start,length);
	    		getParameter = false;
	    	}
	    }
	}
}
