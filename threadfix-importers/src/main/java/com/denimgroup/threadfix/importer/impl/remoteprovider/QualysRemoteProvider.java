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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.io.InputStream;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * TODO use POST data to pre-filter web requests
 * @author mcollins
 *
 */
public class QualysRemoteProvider extends RemoteProvider {
	
	public String getType() {
		return ScannerType.QUALYSGUARD_WAS.getFullName();
	}
	
	private String username = null;
	private String password = null;
	
	private static final Map<String, String> SEVERITIES_MAP = new HashMap<>();
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

    RemoteProviderHttpUtils utils = new RemoteProviderHttpUtilsImpl<>(this.getClass());
	
	public QualysRemoteProvider() {
		super(ScannerType.QUALYSGUARD_WAS);
	}

	@Override
	public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
		if (remoteProviderApplication == null || 
				remoteProviderApplication.getRemoteProviderType() == null) {
			LOG.error("Null input to Qualys getScan(), returning null.");
			return null;
		}
		
		password = remoteProviderApplication.getRemoteProviderType().getPassword();
		username = remoteProviderApplication.getRemoteProviderType().getUsername();
		
		List<String> scanIds = mostRecentScanForApp(remoteProviderApplication);
		
		if (scanIds == null || scanIds.size() == 0) {
			LOG.warn("No valid scans were found.");
			return null;
		}
		
		List<Scan> scanList = list();
		
		for (String scanId : scanIds) {
            HttpResponse response = utils.getUrl(
                    getScanUrl(remoteProviderApplication.getRemoteProviderType()) + scanId, username, password);
			
			if (response.isValid()) {
                inputStream = response.getInputStream();
            } else {
				LOG.warn("Got a " + response.getStatus() + " response code when requesting scan with ID " + scanId +
                        ". Trying the next scan.");
				continue;
			}
	
			QualysWASSAXParser scanParser = new QualysWASSAXParser();
			Scan resultScan = parseSAXInput(scanParser);
			
			if (resultScan != null) {
				LOG.info("The Qualys scan import for scan ID " + scanId + " was successful.");
				resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
				scanList.add(resultScan);
			} else {
				LOG.warn("The Qualys scan import for scan ID " + scanId + " failed!!");
			}
		}
		
		return scanList;
	}

	@Override
	public List<RemoteProviderApplication> fetchApplications() {
		if (remoteProviderType == null || remoteProviderType.getUsername() == null ||
				remoteProviderType.getPassword() == null) {
			LOG.error("Insufficient credentials given to Qualys fetchApplications().");
			return null;
		}
		
		LOG.info("Fetching Qualys applications.");
		
		password = remoteProviderType.getPassword();
		username = remoteProviderType.getUsername();

		// POST with no parameters
		// TODO include filters
		HttpResponse connection = utils.postUrl(getAppsUrl(remoteProviderType), new String[]{}, new String[]{}, username, password);

		InputStream stream;
        if (connection.isValid()) {
            stream = connection.getInputStream();
        } else {
            LOG.warn("Failed to retrieve the applications. Check your credentials. status code was " +
                    connection.getStatus());
            return null;
        }

		QualysAppsParser parser = new QualysAppsParser();
		
		parse(stream, parser);
		
		if (parser.list.size() > 0) {
			LOG.info("Number of Qualys applications: " + parser.list.size());
		} else {
			LOG.warn("No Qualys applications were found. Check your configuration.");
		}
		
		return parser.list;
	}
	
	public List<String> mostRecentScanForApp(RemoteProviderApplication app) {
		if (app == null || app.getNativeId() == null) {
			return null;
		}

		// POST with no parameters
		// TODO include filters
		HttpResponse response = utils.postUrl(getScansForAppUrl(app.getRemoteProviderType()),new String[]{},new String[]{}, username, password);
        InputStream stream;
		if (response.isValid()) {
            stream = response.getInputStream();
        } else {
            LOG.warn("Unable to retrieve scans for the application " + app.getNativeId() + ". Got response code " + response.getStatus());
            return null;
        }

		QualysScansForAppParser parser = new QualysScansForAppParser();
		parse(stream, parser);
		
		List<String> scanIds = list();

		// This should be replaced with the filtered code
		for (Map<String, String> map : parser.list) {
			if (app.getNativeId().equals(map.get("webAppName")) && map.get("date") != null) {
                Calendar mapDate = DateUtils.getCalendarFromString("yyyy-MM-DD'T'HH:mm:ss'Z'", map.get("date"));
				if (mapDate != null && (app.getLastImportTime() == null ||
                        mapDate.after(app.getLastImportTime()))) {
					scanIds.add(map.get("id"));
				}
			}
		}
		
		LOG.info("Returning scan IDs " + scanIds + " for application " + app.getNativeId());

		return scanIds;
	}
	
	public static String getScansForAppUrl(RemoteProviderType type) {
		return "https://qualysapi.qualys." + 
				getLocation(type.getIsEuropean()) + 
				"/qps/rest/3.0/search/was/wasscan";
	}

    public static String getScanUrl(RemoteProviderType type) {
		return "https://qualysapi.qualys." + 
				getLocation(type.getIsEuropean()) + 
				"/qps/rest/3.0/download/was/wasscan/";
	}

    public static String getAppsUrl(RemoteProviderType type) {
		return "https://qualysapi.qualys." + 
				getLocation(type.getIsEuropean()) + 
				"/qps/rest/3.0/search/was/webapp";
	}
	
	private static String getLocation(boolean isEuropean) {
		return isEuropean ? "eu" : "com";
	}
	
	// PARSER CLASSES

	private class QualysAppsParser extends HandlerWithBuilder {

        @Nonnull
		public List<RemoteProviderApplication> list = list();
		
		private boolean getName = false;

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if (qName.equals("name")) {
	    		getName = true;
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getName) {
	    		String tempNameString = getBuilderText();
	    		
	    		RemoteProviderApplication remoteProviderApplication = new RemoteProviderApplication();
	    		remoteProviderApplication.setNativeId(tempNameString);
	    		remoteProviderApplication.setRemoteProviderType(remoteProviderType);
	    		list.add(remoteProviderApplication);
	    		
	    		getName = false;
	    	}
	    }

		public void characters (char ch[], int start, int length) {
	    	if (getName) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
	
	private class QualysScansForAppParser extends HandlerWithBuilder {
		
		public List<Map<String,String>> list = list();
		
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
	    	if (getId) {
	    		currentId = getBuilderText();
	    		getId = false;
	    	} else if (getStatus) {
	    		currentStatus = getBuilderText();
	    		getStatus = false;
	    	} else if (getDate) {
	    		currentDate = getBuilderText();
	    		getDate = false;
	    	} else if (getName) {
                webAppName = getBuilderText();
	    		getName = false;
		    }
	    	
	    	if (qName.equals("WasScan")) {
	    		Map<String, String> map = new HashMap<>();
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
	    	if (getId || getStatus || getDate || getName) {
	    		addTextToBuilder(ch,start,length);
		    }
	    }
	}
	
	private class QualysWASSAXParser extends HandlerWithBuilder {
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
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = DateUtils.getCalendarFromString("yyyy-MM-DD'T'HH:mm:ss'Z'", tempDateString);
	    		}
	    		getDate = false;
	    	} else if (getUri) {
	    		currentPath = getBuilderText();
	    		getUri = false;
	    	} else if (getChannelVulnName) {
	    		currentChannelVulnCode = getBuilderText();
	    		getChannelVulnName = false;
	    	} else if (getParameter) {
	    		currentParameter = getBuilderText();
	    		getParameter = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || getUri || getChannelVulnName || getParameter) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
}
