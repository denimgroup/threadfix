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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.QualysPlatform;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.ScanUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.io.InputStream;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

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
    private String platform = null;

	private static final Map<String, String> SEVERITIES_MAP = new HashMap<String, String>() {{
        put("150000","5");
        put("150001","5");
        put("150002","5");
        put("150003","5");
        put("150004","2");
        put("150005","2");
        put("150006","1");
        put("150007","1");
        put("150008","1");
        put("150009","1");
        put("150010","1");
        put("150011","3");
        put("150012","5");
        put("150013","5");
        put("150014","1");
        put("150015","1");
        put("150016","2");
        put("150017","1");
        put("150018","2");
        put("150019","2");
        put("150020","1");
        put("150021","1");
        put("150022","3");
        put("150023","2");
        put("150024","1");
        put("150025","1");
        put("150026","1");
        put("150028","1");
        put("150029","1");
        put("150030","1");
        put("150032","3");
        put("150033","3");
        put("150034","3");
        put("150035","1");
        put("150036","1");
        put("150037","1");
        put("150038","1");
        put("150039","1");
        put("150040","1");
        put("150041","1");
        put("150042","3");
        put("150043","1");
        put("150044","3");
        put("150045","3");
        put("150046","5");
        put("150047","5");
        put("150048","5");
        put("150049","4");
        put("150051","3");
        put("150052","5");
        put("150053","3");
        put("150054","1");
        put("150055","5");
        put("150056","2");
        put("150057","5");
        put("150058","1");
        put("150059","1");
        put("150060","5");
        put("150061","1");
        put("150062","5");
        put("150063","1");
        put("150064","1");
        put("150065","2");
        put("150066","1");
        put("150067","3");
        put("150068","1");
        put("150069","4");
        put("150071","3");
        put("150072","2");
        put("150076","4");
        put("150077","1");
        put("150078","1");
        put("150079","3");
        put("150080","3");
        put("150081","1");
        put("150082","1");
        put("150083","1");
        put("150084","1");
        put("150085","3");
        put("150086","3");
        put("150087","1");
        put("150088","1");
        put("150089","3");
        put("150090","5");
        put("150092","5");
        put("150093","5");
        put("150094","1");
        put("150095","1");
        put("150097","1");
        put("150098","2");
        put("150099","1");
        put("150100","1");
        put("150101","1");
        put("150103","1");
        put("150104","1");
        put("150105","1");
        put("150106","1");
        put("150107","1");
        put("150108","1");
        put("150109","1");
        put("150111","1");
        put("150112","2");
        put("150114","3");
        put("150115","1");
        put("150116","1");
        put("150118","1");
        put("150120","3");
        put("150121","3");
        put("150122","2");
        put("150123","2");
        put("150124","3");
        put("150125","1");
        put("150127","5");
        put("150128","1");
        put("150129","2");
        put("150134","5");
    }};

    RemoteProviderHttpUtils utils = new RemoteProviderHttpUtilsImpl<>(this.getClass());
	
	public QualysRemoteProvider() {
		super(ScannerType.QUALYSGUARD_WAS);
	}

    private enum QualysScanDetailParam {
        ACTION("action"),
        DETAILS("details"),
        IDS("ids");

        private String param;

        QualysScanDetailParam(String param) {
            this.param = param;
        }

        public String getParam() {
            return this.param;
        }
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

            Set<String> qidSet = set();

            for (Finding finding : resultScan) {
                qidSet.add(finding.getChannelVulnerability().getCode());
            }

            String qids = CollectionUtils.join(",", qidSet);

            String[] parameters = {
                    QualysScanDetailParam.ACTION.getParam(),
                    QualysScanDetailParam.IDS.getParam(),
                    QualysScanDetailParam.DETAILS.getParam()
            };

            String[] values = {"list", qids, "All"};
            String[] headerNames = {"X-Requested-With", "Content-Type"};
            String[] headerVals = {"Curl", "application/x-www-form-urlencoded"};

            response = utils.postUrl(getScanDetailsUrl(remoteProviderApplication.getRemoteProviderType()), parameters, values, username, password, headerNames, headerVals);
            if (response.isValid()) {
                inputStream = response.getInputStream();

                parseQualysSAXInput();

                LOG.info("Retrieved additional scanner details for QID: " + qids);
            } else {
                LOG.warn("Unable to retrieve scan details for the application " + remoteProviderApplication.getNativeName() + ". Got response code " + response.getStatus());
            }

            LOG.info("The Qualys scan import for scan ID " + scanId + " was successful.");

            resultScan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());
            scanList.add(resultScan);
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
		if (app == null || app.getNativeName() == null) {
			return null;
		}

		// POST with no parameters
		// TODO include filters
		HttpResponse response = utils.postUrl(getScansForAppUrl(app.getRemoteProviderType()),new String[]{},new String[]{}, username, password);
        InputStream stream;
		if (response.isValid()) {
            stream = response.getInputStream();
        } else {
            LOG.warn("Unable to retrieve scans for the application " + app.getNativeName() + ". Got response code " + response.getStatus());
            return null;
        }

		QualysScansForAppParser parser = new QualysScansForAppParser();
		parse(stream, parser);
		
		List<String> scanIds = list();

		// This should be replaced with the filtered code
		for (Map<String, String> map : parser.list) {
			if (app.getNativeName().equals(map.get("webAppName")) && map.get("date") != null) {
                Calendar mapDate = DateUtils.getCalendarFromUTCString(map.get("date"));
				if (mapDate != null && (app.getLastImportTime() == null ||
                        mapDate.after(app.getLastImportTime()))) {
					scanIds.add(map.get("id"));
				}
			}
		}
		
		LOG.info("Returning scan IDs " + scanIds + " for application " + app.getNativeName());

		return scanIds;
	}

    private static String getBaseUrl(RemoteProviderType type) {

        QualysPlatform qp;
        String platform = type.getPlatform();

        if (platform == null || platform.isEmpty()) {
            qp = type.getIsEuropean() ? QualysPlatform.EU : QualysPlatform.US_1;
        } else {
            qp = QualysPlatform.getPlatform(platform);
        }

        return qp.getUrl();
    }
	
	public static String getScansForAppUrl(RemoteProviderType type) {
		return getBaseUrl(type) + "/qps/rest/3.0/search/was/wasscan";
	}

    public static String getScanUrl(RemoteProviderType type) {
		return getBaseUrl(type) + "/qps/rest/3.0/download/was/wasscan/";
	}

    public static String getAppsUrl(RemoteProviderType type) {
		return getBaseUrl(type) + "/qps/rest/3.0/search/was/webapp";
	}

    public static String getScanDetailsUrl(RemoteProviderType type) {
        return getBaseUrl(type) + "/api/2.0/fo/knowledge_base/vuln/";
    }


    // PARSE FUNCTION

    @Nonnull
    private void parseQualysSAXInput() {
        log.debug("Starting Qualys SAX Parsing.");

        if (inputStream == null) {
            throw new IllegalStateException("InputStream was null. Can't parse SAX input. This is probably a coding error.");
        }

        // we don't need the state from the details parser so we can just pass the new object in
        ScanUtils.readSAXInput(new QualysWASSAXDetailsParser(), "Done Parsing.", inputStream);

        if (shouldDeleteAfterParsing) {
            deleteScanFile();
        }
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
	    		remoteProviderApplication.setNativeName(tempNameString);
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
		private Boolean getAttackDetail       = false;

		private String currentChannelVulnCode = null;
		private String currentPath            = null;
		private String currentParameter       = null;
		private String currentSeverityCode    = null;
		private String currentAttackDetail    = null;

        private Map<FindingKey, String> findingMap = new HashMap<>();

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
				      String qName, Attributes atts) {

            switch(qName) {
                case "launchedDate":
                    getDate = true;
                    break;
                case "uri":
                    getUri = true;
                    break;
                case "qid":
                    getChannelVulnName = true;
                    break;
                case "param":
                    getParameter = true;
                    break;
                case "payload":
                    getAttackDetail = true;
                    break;
                case "instances":
                    currentSeverityCode = SEVERITIES_MAP.get(currentChannelVulnCode);

                    if (currentSeverityCode == null) {
                        LOG.warn("Unable to retrieve severity for code " + currentChannelVulnCode + ". Setting to 3");
                        currentSeverityCode = "3";
                    }

                    findingMap.put(FindingKey.PATH,             currentPath);
                    findingMap.put(FindingKey.PARAMETER,        currentParameter);
                    findingMap.put(FindingKey.VULN_CODE,        currentChannelVulnCode);
                    findingMap.put(FindingKey.SEVERITY_CODE,    currentSeverityCode);
                    findingMap.put(FindingKey.VALUE,            currentAttackDetail);

                    Finding finding = constructFinding(findingMap);
                    add(finding);

                    currentParameter       = null;
                    currentPath            = null;
                    getParameter           = false;
                    break;
            }
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			date = DateUtils.getCalendarFromUTCString(tempDateString);
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
            } else if (getAttackDetail) {
                currentAttackDetail = getBuilderText();
                getAttackDetail = false;
            }
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || getUri || getChannelVulnName || getParameter || getAttackDetail) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}

    private class QualysWASSAXDetailsParser extends HandlerWithBuilder {
        private Boolean getDiagnosis        = false;
        private Boolean getConsequence      = false;
        private Boolean getSolution         = false;
        private Boolean getQid              = false;

        private String currentQid           = null;
        private String currentDiagnosis     = null;
        private String currentConsequence   = null;
        private String currentSolution      = null;

        private Map<FindingKey, String> findingMap = new HashMap<>();

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
            if (qName.equalsIgnoreCase("diagnosis")) {
                getDiagnosis = true;

            } else if (qName.equalsIgnoreCase("consequence")) {
                getConsequence = true;

            }  else if (qName.equalsIgnoreCase("qid")) {
                getQid = true;

            } else if (qName.equalsIgnoreCase("solution")) {
                getSolution = true;

            } else if (qName.equalsIgnoreCase("discovery")) {
                String currentDetail = currentDiagnosis + currentConsequence;
                findingMap.put(FindingKey.RECOMMENDATION,   currentSolution);
                findingMap.put(FindingKey.DETAIL,           currentDetail);

                for(Finding finding : saxFindingList) {
                    if(finding.getChannelVulnerability().getCode().equals(currentQid)
                            && finding.getScannerDetail() == null && finding.getScannerRecommendation() == null){
                        findingMap.put(FindingKey.VALUE, finding.getAttackString());
                        addFindingDetail(finding, findingMap);
                    }
                }
            }
        }

        public void endElement(String uri, String name, String qName) {
            if (getDiagnosis) {
                currentDiagnosis = getBuilderText();
                getDiagnosis = false;
            } else if (getConsequence) {
                currentConsequence = getBuilderText();
                getConsequence = false;
            } else if (getQid) {
                currentQid = getBuilderText();
                getQid = false;
            } else if (getSolution) {
                currentSolution = getBuilderText();
                getSolution = false;
            }
        }

        public void characters (char ch[], int start, int length) {
            if (getDiagnosis || getConsequence || getSolution || getQid) {
                addTextToBuilder(ch, start, length);
            }
        }
    }
}
