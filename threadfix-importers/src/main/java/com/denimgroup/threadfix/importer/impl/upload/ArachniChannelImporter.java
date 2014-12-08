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
import com.denimgroup.threadfix.annotations.StartingTagSet;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerDatabaseNames;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import javax.annotation.Nonnull;
import java.net.URL;
import java.util.Calendar;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 *
 * @author mcollins
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.ARACHNI_DB_NAME,
        startingXMLTagSets = {
                @StartingTagSet({"arachni_report", "title", "generated_on", "report_false_positives", "system", "version", "revision"}),
                @StartingTagSet({"report", "version", "options"})
        }
)
public class ArachniChannelImporter extends AbstractChannelImporter {
	
	private static Map<String, FindingKey> tagMap = map(
		"name", FindingKey.VULN_CODE,
		"severity", FindingKey.SEVERITY_CODE,
		"variable", FindingKey.PARAMETER,
		"var", FindingKey.PARAMETER,
		"url", FindingKey.PATH,
		"injected", FindingKey.VALUE,
		"request", FindingKey.REQUEST,
		"html", FindingKey.RESPONSE,
		"description", FindingKey.DETAIL,
		"remedy_guidance", FindingKey.RECOMMENDATION,
		"rawfinding", FindingKey.RAWFINDING,
        "cwe", FindingKey.CWE,
        "severity", FindingKey.SEVERITY_CODE
    );

    private StringBuffer currentRawFinding = new StringBuffer();
    String requestMethod = null;
    boolean getMethodText = false;
	// Since the severity mappings are static and not included in the XML output,
	// these have been reverse engineered from the code
	private static Map<String, String> severityMap = new HashMap<>();
	static {
		severityMap.put("Allowed HTTP methods", "INFORMATIONAL");
		severityMap.put("A backdoor file exists on the server.", "HIGH");
		severityMap.put("A backup file exists on the server.", "HIGH");
		severityMap.put("Code injection", "HIGH");
		severityMap.put("Code injection (timing attack)", "HIGH");
		severityMap.put("A common directory exists on the server.", "MEDIUM");
		severityMap.put("A common sensitive file exists on the server.", "LOW");
		severityMap.put("Cross-Site Request Forgery", "HIGH");
		severityMap.put("Directory listing is enabled.", "LOW");
		severityMap.put("Misconfiguration in LIMIT directive of .htaccess file.", "HIGH");
		severityMap.put("HTTP PUT is enabled.", "HIGH");
		severityMap.put("Interesting server response.", "INFORMATIONAL");
		severityMap.put("LDAP Injection", "HIGH");
		severityMap.put("Operating system command injection", "HIGH");
		severityMap.put("Operating system command injection (timing attack)", "HIGH");
		severityMap.put("Path Traversal", "MEDIUM");
		severityMap.put("Response splitting", "MEDIUM");
		severityMap.put("Remote file inclusion", "HIGH");
		severityMap.put("SQL Injection", "HIGH");
		severityMap.put("Blind SQL Injection", "HIGH");
		severityMap.put("Blind SQL Injection (timing attack)", "HIGH");
		severityMap.put("Unencrypted password form.", "MEDIUM");
		severityMap.put("Unvalidated redirect", "MEDIUM");
		severityMap.put("WebDAV", "INFORMATIONAL");
		severityMap.put("XPath Injection", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS)", "HIGH");
		severityMap.put("Cross-Site Scripting in event tag of HTML element.", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS) in path", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML \"script\" tag.", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML tag.", "HIGH");
		severityMap.put("Cross-Site Scripting in HTML &quot;script&quot; tag.", "HIGH");
		severityMap.put("Cross-Site Scripting (XSS) in URI", "HIGH");
		severityMap.put("The TRACE HTTP method is enabled.", "MEDIUM");
		severityMap.put("Found a CAPTCHA protected form.", "INFORMATIONAL");
		severityMap.put("Credit card number disclosure.", "MEDIUM");
		severityMap.put("CVS/SVN user disclosure.", "LOW");
		severityMap.put("Disclosed e-mail address.", "INFORMATIONAL");
		severityMap.put("Found an HTML object.", "INFORMATIONAL");
		severityMap.put("Private IP address disclosure.", "LOW");
		severityMap.put("Disclosed US Social Security Number.", "HIGH");
        //Fixes bug 444
        severityMap.put("Code injection (php://input wrapper)", "HIGH");
        severityMap.put("File Inclusion", "HIGH");
        severityMap.put("Remote File Inclusion", "HIGH");
        severityMap.put("Session fixation", "HIGH");
        severityMap.put("Source code disclosure", "HIGH");
        severityMap.put("Blind SQL Injection (differential analysis)", "HIGH");
        severityMap.put("Cross-Site Scripting in event tag of HTML element", "HIGH");
        severityMap.put("Cross-Site Scripting in HTML 'script' tag", "HIGH");
        severityMap.put("Cross-Site Scripting in HTML \\'script\\' tag", "HIGH");
        severityMap.put("Cross-Site Scripting (XSS) in HTML tag", "HIGH");
        severityMap.put("A backdoor file exists on the server", "HIGH");
        severityMap.put("Backup file", "MEDIUM");
        severityMap.put("Common directory", "MEDIUM");
        severityMap.put("Common sensitive file", "LOW");
        severityMap.put("Directory listing", "LOW");
        severityMap.put("Misconfiguration in LIMIT directive of .htaccess file", "HIGH");
        severityMap.put("Publicly writable directory", "HIGH");
        severityMap.put("Interesting response", "INFORMATIONAL");
        severityMap.put("Exposed localstart.asp page", "LOW");
        severityMap.put("Access restriction bypass via X-Forwarded-For", "HIGH");
        severityMap.put("HTTP TRACE", "MEDIUM");

	}

    public static final String FORMAT_STRING = "yyyy-MM-dd'T'HH:mm:ss";
    private static final String TIME_ZONE_PATTERN = ".*[0-9]T[0-9].*";

    public ArachniChannelImporter() {
        super(ScannerType.ARACHNI);
    }

    @Override
    public Scan parseInput() {
        return parseSAXInput(new ArachniSAXParser());
    }

    public class ArachniSAXParser extends HandlerWithBuilder {

        private boolean getDate   = false;
        private boolean inFinding = false;
        private boolean inRequest = false; //for accumulating request headers

        boolean gettingSeed = false;
        String lastSeed;

        private FindingKey itemKey = null;

        private Map<FindingKey, String> findingMap = null;

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

        public void startElement(String uri, String name,
                                 String qName, Attributes atts) {
            if ("finish_datetime".equals(qName)) {
                getDate = true;
            } else if ("issue".equals(qName)) {
                findingMap = new EnumMap<>(FindingKey.class);
                // set the inFinding flag to accumulate elements and character info for raw xml synthesis
                inFinding = true;

            } else if (inFinding && tagMap.containsKey(qName)) {
                itemKey = tagMap.get(qName);
                //the Arachni finding request is stored in a list of header element 'field' tags rather than the raw request itself
                //so we need to rebuild it.  we start tracking 'field' elements when we hit the request element
                if ("request".equals(qName)) {
                    inRequest = true;
                    // this will be the first line of the request
                    String requestLine = findingMap.get(FindingKey.PATH); //sane default

                    try { //mimicry
                        requestLine = requestMethod + " " + (new URL(findingMap.get(FindingKey.PATH))).getPath() + " HTTP/1.x (computed)\n";
                    } catch (Exception ignored) {
                        log.error("Got exception while attempting to construct a request line: " + ignored.getMessage());
                        log.error("Continuing.");
                    }

                    //store this first line
                    findingMap.put(FindingKey.REQUEST, requestMethod + " " + requestLine);
                } else {

                    //ensure that we stop recording these so we don't pick up response headers
                    inRequest = false;
                }
                getBuilderText(); //resets the stringbuffer so we aren't pulling in data from unrelated elements
            } else if ("method".equals(qName)) {
                getMethodText = true;
                getBuilderText(); //empty out buffer so we get the method alone for request header rebuilding above

            } else if ("seed".equals(qName)) {
                lastSeed = null;
                gettingSeed = true;
                getBuilderText();

            } else if ("input".equals(qName) &&
                    lastSeed != null &&
                    atts.getValue("value") != null &&
                    atts.getValue("value").contains(lastSeed)) {
                findingMap.put(FindingKey.PARAMETER, atts.getValue("name"));
                lastSeed = null;

            } else if (inRequest && "field".equals(qName)) {
                //this is where we accumulate request headers.  start by forming a line from the element attributes
                String header = atts.getValue("name") + ": " + atts.getValue("value") + "\n";

                if (!findingMap.containsKey(FindingKey.REQUEST)) {
                    findingMap.put(FindingKey.REQUEST, header);  //this should never hit b/c the request line was formed above
                } else {
                    //append the new header line to the existing string.  a stringbuffer would probably be better
                    findingMap.put(FindingKey.REQUEST, findingMap.get(FindingKey.REQUEST) + header);
                }
            }
            if (inFinding) {
                currentRawFinding.append(makeTag(name, qName, atts));
            }
        }

        public void endElement(String uri, String name, String qName) {
            if (inFinding)
                currentRawFinding.append("</").append(qName).append(">");

            if ("method".equals(qName)) {
                requestMethod = getBuilderText();
                getMethodText = false;
            }

            if ("issue".equals(qName)) {
                // TODO instead look into why this error occurs

                if (findingMap.get(FindingKey.VULN_CODE) != null &&
                        findingMap.get(FindingKey.VULN_CODE).equals("Cross-Site Scripting in HTML ")) {
                    findingMap.put(FindingKey.VULN_CODE,
                            "Cross-Site Scripting in HTML &quot;script&quot; tag.");
                }

                //left in place for old versions of Arachni

                if (findingMap.containsKey(FindingKey.SEVERITY_CODE)) {
                    findingMap.put(FindingKey.SEVERITY_CODE, findingMap.get(FindingKey.SEVERITY_CODE).toUpperCase());
                }

                if (!findingMap.containsKey(FindingKey.SEVERITY_CODE) || findingMap.get(FindingKey.SEVERITY_CODE) == null)
                    findingMap.put(FindingKey.SEVERITY_CODE, severityMap.get(findingMap.get(FindingKey.VULN_CODE)));
                if (findingMap.get(FindingKey.SEVERITY_CODE) == null || findingMap.get(FindingKey.SEVERITY_CODE).isEmpty())
                    findingMap.put(FindingKey.SEVERITY_CODE, severityMap.get(findingMap.get(FindingKey.VULN_CODE)));
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
                // Set CWE 16 Configuration if there no CWE in scan file
                if (findingMap.get(FindingKey.CWE) == null || findingMap.get(FindingKey.CWE).isEmpty())
                    findingMap.put(FindingKey.CWE, "16");
                Finding finding = constructFinding(findingMap);

                add(finding);
                findingMap = null;
                inFinding = false;
                currentRawFinding.setLength(0);

            } else if (inFinding && itemKey != null) {
                String currentItem = getBuilderText();

                if (currentItem != null && "RESPONSE".equals(itemKey.toString())) {
                    //these are base64 encoded in the xml
                    try {
                        currentItem = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(currentItem));
                    } catch (Exception ignored) {
                        //if it can't be decoded just pass as-is
                    }
                }

                if ("request".equals(qName)) {
                    inRequest = false;
                }

                if (currentItem != null && findingMap.get(itemKey) == null) {
                    findingMap.put(itemKey, currentItem);
                }
                itemKey = null;
            } else if ("seed".equals(qName)) {
                lastSeed = getBuilderText();
                gettingSeed = false;
            }

            if (getDate) {
                String tempDateString = getBuilderText();

                if (tempDateString != null && !tempDateString.trim().isEmpty()) {
                    date = getDateFromString(tempDateString);
                }
	    		getDate = false;
	    	} 
	    }

	    public void characters (char ch[], int start, int length) {
	    	if (getDate || itemKey != null || getMethodText || gettingSeed) {
                addTextToBuilder(ch, start, length);
            }
	    	if (inFinding){
	    		currentRawFinding.append(ch, start, length);
	    	}
	    }
	}

    Calendar getDateFromString(String tempDateString) {
        if (tempDateString.matches(TIME_ZONE_PATTERN)) {
            return DateUtils.getCalendarFromString(FORMAT_STRING, tempDateString);
        } else {
            return DateUtils.getCalendarFromString("EEE MMM dd kk:mm:ss yyyy", tempDateString);
        }
    }

    @Nonnull
    @Override
	public ScanCheckResultBean checkFile() {
		return testSAXInput(new ArachniSAXValidator());
	}
	
	public class ArachniSAXValidator extends HandlerWithBuilder {
		private boolean hasFindings = false;
		private boolean hasDate = false;
		private boolean correctFormat = false;
		private boolean getDate = false;
		
	    private void setTestStatus() {
	    	if (!correctFormat)
	    		testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
	    	else if (hasDate)
	    		testStatus = checkTestDate();
	    	if ((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings)
	    		testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
	    	else if (testStatus == null)
	    		testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
	    }

	    ////////////////////////////////////////////////////////////////////
	    // Event handlers.
	    ////////////////////////////////////////////////////////////////////
	    
	    public void endDocument() {
	    	setTestStatus();
	    }

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {	    	
	    	if ("arachni_report".equals(qName)) {
	    		correctFormat = true;
	    	} else if ("report".equals(qName) && atts.getValue(0) != null && atts.getValue(0).contains("Arachni")) {
                correctFormat = true;
            }
	    	
	    	if ("finish_datetime".equals(qName)) {
	    		getDate = true;
	    	}
	    	
	    	if ("issue".equals(qName)) {
	    		hasFindings = true;
	    		setTestStatus();
	    		throw new SAXException(FILE_CHECK_COMPLETED);
	    	}
	    }
	    
	    public void endElement(String uri, String name, String qName) {
	    	if (getDate) {
	    		String tempDateString = getBuilderText();

	    		if (tempDateString != null && !tempDateString.trim().isEmpty()) {
	    			testDate = getDateFromString(tempDateString);
	    		}
	    		
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
