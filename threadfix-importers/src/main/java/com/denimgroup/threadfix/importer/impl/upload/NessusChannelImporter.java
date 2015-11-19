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
package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.ScannerUtils.md5;

/**
 * The Nessus importer behaves much like the DependencyCheck and Sonatype importers
 * These support their own types (CVE, Nessus, osvdb) instead of CWEs
 *
 * @author mcollins
 */
@ScanImporter(scannerName = ScannerDatabaseNames.NESSUS_DB_NAME, startingXMLTags = {"NessusClientData_v2"})
public class NessusChannelImporter extends AbstractChannelImporter {

	private static final String SIMPLE_HTTP_REGEX = "(http[^\n]*)";
	private static final String URL_COLON_REGEX   = "URL  : ([^\n]*)\n";
	private static final String PAGE_COLON_REGEX  = "Page : ([^\n]*)\n";

	private static final String INPUT_NAME_COLON_PARAM_REGEX = "Input name : ([^\n]*)\n";

	private static final List<String> SSL_VULNS =
			Arrays.asList("26928", "60108", "57620", "53360", "42873", "35291");

	private static final Map<String,String> PATH_PARSE_MAP = map();
	static {
		PATH_PARSE_MAP.put("26194", PAGE_COLON_REGEX);
		PATH_PARSE_MAP.put("11411", URL_COLON_REGEX);
		PATH_PARSE_MAP.put("40984", SIMPLE_HTTP_REGEX);
	}

	private static final Map<String,String> PARAM_PARSE_MAP = map();
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
		private Boolean getNameText           = false;
		private Boolean getHost               = false;
        private Boolean getScannerDetail = false;
        private Boolean getScannerRecommendation = false;
        private Boolean inFinding = false;
        private Boolean getCwe = false;

		private String currentSeverityCode, host, currentChannelVulnCode;
		private String pluginName, currentHost, currentPort;
        private String currentDetail = null;
        private String currentRecommendation = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();
        private String cwe = null;

        Map<FindingKey, String> findingMap = map();

	    public void add(Finding finding) {
			if (finding != null) {
	    		finding.setIsStatic(false);
                if ( finding.getChannelSeverity() != null) {
                    saxFindingList.add(finding);
                }
    		}
	    }

	    //Once the entire string has been taken out of characters(), parse it
	    public void parseFindingString() {
			parseGenericPattern();

    		currentChannelVulnCode = null;
    		currentSeverityCode = null;
			cwe = null;

			currentRecommendation = null;
			currentRawFinding.setLength(0);
	    }

	    private void parseGenericPattern() {
	    	String param = "", path = "Network";

            add(createFinding(path, param));
	    }

        private Finding createFinding(String url, String param) {

            findingMap.put(FindingKey.PATH, url);
            findingMap.put(FindingKey.PARAMETER, param);
            findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
            findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
            findingMap.put(FindingKey.RECOMMENDATION, currentRecommendation);
            findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
            findingMap.put(FindingKey.CWE, (cwe == null ? "16" : cwe));

			Finding finding = constructFinding(findingMap);
			Dependency dependency = new Dependency();

			if (finding != null) {
				String component = currentHost + ":" + currentPort;
				dependency.setComponentName(component);
				dependency.setSource("nessus");
				dependency.setCve(currentChannelVulnCode);
				dependency.setComponentFilePath(component);
				dependency.setDescription(currentDetail);
				finding.setDependency(dependency);
				String info = dependency.getComponentFilePath() + " " + dependency.getCve();
				finding.setNativeId(md5(info));
			}

			return finding;
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
				currentPort = atts.getValue("port");
				pluginName = atts.getValue("pluginName");
                inFinding = true;
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
            } else if ("ReportHost".equalsIgnoreCase(qName)) {
				currentHost = atts.getValue("name");
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
                inFinding = false;
            }
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || getNameText || getHost || getScannerDetail || getScannerRecommendation || getCwe) {
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

			if (testStatus == null) {
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
