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
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TODO import more scans and make sure parameters and paths 
 * are parsed correctly for all vuln types.
 * 
 * @author mcollins
 */
@ScanImporter(scannerName = ScannerDatabaseNames.NESSUS_DB_NAME, startingXMLTags = {"NessusClientData_v2"})
public class NessusChannelImporter extends AbstractChannelImporter {

	private static final String SIMPLE_HTTP_REGEX = "(http[^\n]*)";
	private static final String URL_COLON_REGEX   = "URL  : ([^\n]*)\n";
	private static final String PAGE_COLON_REGEX  = "Page : ([^\n]*)\n";

	private static final String CSRF_PATH_START = "The following CGIs are not protected by a random token :";
	private static final String CSRF_VULN_CODE = "56818";

	private static final String INPUT_NAME_COLON_PARAM_REGEX = "Input name : ([^\n]*)\n";

	private static final List<String> SSL_VULNS =
			Arrays.asList("26928", "60108", "57620", "53360", "42873", "35291");

	private static final Map<String,String> PATH_PARSE_MAP = new HashMap<>();
	static {
		PATH_PARSE_MAP.put("26194", PAGE_COLON_REGEX);
		PATH_PARSE_MAP.put("11411", URL_COLON_REGEX);
		PATH_PARSE_MAP.put("40984", SIMPLE_HTTP_REGEX);
	}

	private static final Map<String,String> PARAM_PARSE_MAP = new HashMap<>();
	static {
		PARAM_PARSE_MAP.put("26194", INPUT_NAME_COLON_PARAM_REGEX);
	}

	public NessusChannelImporter() {
		super(ScannerType.NESSUS);
	}

	@Override
	public Scan parseInput() {
		return parseSAXInput(new NessusSAXParser());
	}

	public class NessusSAXParser extends HandlerWithBuilder {
		private Boolean getDate               = false;
		private Boolean getFindings           = false;
		private Boolean getNameText           = false;
		private Boolean getHost               = false;
        private Boolean getScannerDetail = false;
        private Boolean getScannerRecommendation = false;
        private Boolean inFinding = false;
        private Boolean getCwe = false;

		private String currentChannelVulnCode = null;
		private String currentSeverityCode    = null;
		private String host                   = null;
        private String currentDetail = null;
        private String currentRecommendation = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();
        private String cwe = null;

        Map<FindingKey, String> findingMap = new HashMap<>();

		private String pluginOutputString = null;

		private String infoLineParamRegex = "\\+ The '([^&]+)' parameter of the [^ ]+ CGI :";
		private String infoLinePathRegex = "\\+ The '[^&]+' parameter of the ([^ ]+) CGI :";

	    public void add(Finding finding) {
			if (finding != null) {
    			finding.setNativeId(getNativeId(finding));
	    		finding.setIsStatic(false);
                if ( finding.getChannelSeverity() != null) {
                    saxFindingList.add(finding);
                }
    		}
	    }

	    //Once the entire string has been taken out of characters(), parse it
	    public void parseFindingString() {
	    	if (pluginOutputString == null)
	    		return;

	    	String stringResult = pluginOutputString;
	    	if (stringResult.trim().isEmpty())
	    		return;

	    	if (PATH_PARSE_MAP.containsKey(currentChannelVulnCode)) {
	    		parseRegexMatchesAndAdd(stringResult);
	    	} else if (SSL_VULNS.contains(currentChannelVulnCode)){
	    		add(createFinding("Application Server", null));
	    	} else if (CSRF_VULN_CODE.equals(currentChannelVulnCode)){
	    		parseCSRFAndAdd(stringResult);
	    	} else {
	    		parseGenericPattern(stringResult);
	    	}

    		currentChannelVulnCode = null;
    		currentSeverityCode = null;
            cwe = null;
	    }

	    private void parseCSRFAndAdd(String stringResult) {
	    	if (stringResult != null && stringResult.contains(CSRF_PATH_START)) {
	    		String smallerPart = stringResult.substring(stringResult.indexOf(CSRF_PATH_START) + CSRF_PATH_START.length());
	    		if (smallerPart.contains("\n")) {
	    			for (String line : smallerPart.split("\n")) {
	    				if (line != null && !line.trim().equals("")) {
	    		    		add(createFinding(line.trim(), null));
	    				}
	    			}
	    		}
	    	}
	    }

	    private void parseRegexMatchesAndAdd(String stringResult) {
	    	String paramRegex = null,    pathRegex  = PATH_PARSE_MAP.get(currentChannelVulnCode);
    		Matcher paramMatcher = null, pathMatcher = Pattern.compile(pathRegex).matcher(stringResult);

    		if (PARAM_PARSE_MAP.containsKey(currentChannelVulnCode)) {
    			paramRegex = PARAM_PARSE_MAP.get(currentChannelVulnCode);
    			paramMatcher = Pattern.compile(paramRegex).matcher(stringResult);
    		}

    		//int count = 1;
    		while (pathMatcher.find()) {
    			String param = null;
    			if (paramMatcher != null && paramMatcher.find(pathMatcher.start())) {
    				param = paramMatcher.group(1);
    			}

    			String path = pathMatcher.group(1);

    			if (path != null && host != null && !path.startsWith("http"))
    				path = host + path;

	    		add(createFinding(path, param));
    		}
	    }

	    private void parseGenericPattern(String stringResult) {
	    	String param = "", path = "/";

            if (stringResult.contains("\n")) {
	    		String [] lines = stringResult.split("\n");

	    		for (String line : lines) {

	    			if (line == null || !line.contains("+ The '")) {
	    				continue;
	    			}

	    			param = RegexUtils.getRegexResult(line, infoLineParamRegex);
	    			path = RegexUtils.getRegexResult(line,infoLinePathRegex);

	    			if (path != null && host != null && !path.startsWith("http"))
	    				path = host + path;

	    		}
	    	}
            add(createFinding(path, param));
    		currentChannelVulnCode = null;
    		currentSeverityCode = null;
	    }

        private Finding createFinding(String url, String param) {

            findingMap.put(FindingKey.PATH, url);
            findingMap.put(FindingKey.PARAMETER, param);
            findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
            findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
            findingMap.put(FindingKey.DETAIL, currentDetail);
            findingMap.put(FindingKey.RECOMMENDATION, currentRecommendation);
            findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
            findingMap.put(FindingKey.CWE, cwe);

            return constructFinding(findingMap);
        }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////

	    public void startElement (String uri, String name,
				      String qName, Attributes atts)
	    {
	    	if ("ReportItem".equals(qName)) {
	    		currentChannelVulnCode = atts.getValue("pluginID");
	    		currentSeverityCode = atts.getValue("severity");
                inFinding = true;
	    	} else if ("plugin_output".equals(qName)) {
	    		getFindings = true;
	    	} else if (date == null && "tag".equals(qName) && "HOST_END".equals(atts.getValue("name"))) {
	    		getDate = true;
	    	} else if (host == null && "name".equals(qName)) {
	    		getNameText = true;
	    	} else if ("description".equals(qName)) {
                getScannerDetail = true;
            } else if ("solution".equals(qName)) {
                getScannerRecommendation = true;
            } else if ("cwe".equalsIgnoreCase(qName)) {
                getCwe = true;
            }

            if (inFinding){
                currentRawFinding.append(makeTag(name, qName , atts));
            }
	    }

	    public void endElement (String uri, String name, String qName)
	    {
            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }

            if (getDate) {
	    		String tempDateString = getBuilderText();
	    		if (tempDateString != null) {
	    			date = DateUtils.getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString.trim());
	    		}
	    		getDate = false;
	    	} else if (getFindings) {
	    		pluginOutputString = getBuilderText();
	    		getFindings = false;
	    	} else if (getNameText) {
	    		String text = getBuilderText();

	    		if ("TARGET".equals(text)) {
	    			getHost = true;
	    		}

	    		getNameText = false;
	    	} else if (getHost) {
	    		String text = getBuilderText();

	    		if (text != null && text.startsWith("http")) {
	    			host = text;
	    			if (host.charAt(host.length()-1) == '/') {
	    				host = host.substring(0,host.length()-1);
	    			}
	    			try {
						URL testUrl = new URL(host);
						host = testUrl.getProtocol() + "://" + testUrl.getHost();
					} catch (MalformedURLException e) {
						log.warn("Nessus parser tried to parse " + host + " as a URL.", e);
					}
	    		}
                    getHost = false;
	    	} else if (getScannerDetail) {
                currentDetail = getBuilderText();
                getScannerDetail = false;
            } else if (getScannerRecommendation) {
                currentRecommendation = getBuilderText();
                getScannerRecommendation = false;
            } else if (getCwe) {
                String vulnCode = getBuilderText();
                if (qName.equals("cwe")) {
                    updateVulnCode(vulnCode);
                }
                getCwe = false;
            } else if ("ReportItem".equals(qName)) {
                parseFindingString();
                pluginOutputString = null;
                inFinding = false;
                currentRawFinding.setLength(0);
            }
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || getFindings || getNameText || getHost || getScannerDetail || getScannerRecommendation || getCwe) {
	    		addTextToBuilder(ch, start, length);
	    	}
            if (inFinding)
                currentRawFinding.append(ch,start,length);
	    }

        private void updateVulnCode(String vulnCode) {

            String stringId = vulnCode.replaceAll("\\D+", "");

            Integer integerId = IntegerUtils.getIntegerOrNull(stringId);

            // This code works because of the 1-1 correspondence of manual channel text and cwe text
            if (integerId != null) {
                GenericVulnerability genericVulnerability =
                        genericVulnerabilityDao.retrieveByDisplayId(integerId);
                if (genericVulnerability != null) {
                    cwe = integerId.toString();
                    findingMap.put(FindingKey.VULN_CODE, genericVulnerability.getName());
                }
            }
        }

    }

	@Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new NessusSAXValidator());
	}

	public class NessusSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;

		private boolean clientDataTag = false;
		private boolean reportTag = false;

	    private void setTestStatus() {
	    	correctFormat = clientDataTag && reportTag;

	    	if (!correctFormat) {
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	} else if (hasDate) {
	    		testStatus = checkTestDate();
	    	}

	    	if ((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings) {
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	} else if (testStatus == null) {
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
	    	if ("NessusClientData_v2".equals(qName)) {
	    		clientDataTag = true;
	    	} else if ("Report".equals(qName)) {
	    		reportTag = true;
	    	} else if ("ReportItem".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	} else if ("tag".equals(qName) && "HOST_END".equals(atts.getValue("name"))) {
	    		getDate = true;
	    	}
	    }

	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();
	    		testDate = DateUtils.getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);

	    		hasDate = testDate != null;

	    		getDate = false;
	    	}
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate) {
	    		addTextToBuilder(ch, start, length);
	    	}
	    }
	}
}
