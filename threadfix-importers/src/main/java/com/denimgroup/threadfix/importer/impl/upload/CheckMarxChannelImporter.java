////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import org.apache.commons.lang3.StringEscapeUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.ScannerUtils.md5;

/**
 *
 * @author mcollins
 *
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.CHECKMARX_DB_NAME,
        startingXMLTags = { "CxXMLResults" }
)
public class CheckMarxChannelImporter extends AbstractChannelImporter {

    public static final String ROOT_NODE_NAME = "CxXMLResults";

    private static final String SCAN_START = "ScanStart",
            VERSION_ATTRIBUTE = "CheckmarxVersion",
            NAME_ATTRIBUTE = "name",
            QUERY = "Query",
            RESULT = "Result",
            NAME = "Name",
            CWE_ID = "cweId",
            SEVERITY = "Severity",
            PATH_NODE = "PathNode",
            NUMBER = "Number",
            LINE = "Line",
            FILE_NAME = "FileName",
            URL = "DeepLink",
            CODE = "Code",
            FALSE_POSITIVE = "FalsePositive";

    // sample is                                                 17-Dec-2013 10:39
    static final SimpleDateFormat format = new SimpleDateFormat("dd-MMM-yyyy HH:mm", Locale.US);
    static final SimpleDateFormat format_EEEE = new SimpleDateFormat("EEEE, MMMMM dd, yyyy hh:mm:ss a", Locale.US);  // Monday, April 06, 2015 5:01:46 PM

    public CheckMarxChannelImporter() {
        super(ScannerType.CHECKMARX);
    }

    @Override
    public Scan parseInput() {
        return parseSAXInput(new CheckMarxScanParser());
    }

    public class CheckMarxScanParser extends HandlerWithBuilder {

        Map<FindingKey, String> findingMap = map();
        // These are per-Query
        String currentCweId = null,
            currentVulnName = null,
            currentSeverity = null;
        String currentQueryBeginTag = null,
                currentQueryEndTag = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();

        // These are per-Result
        String currentFileName = null,
            findingLineNumber = null,
            currentUrlReference = null;

        // These are per-PathNode
        String lineText = null,
            lineNumber = null,
            fileName = null;

        boolean getText = false;
        int currentSequence = 1;
        boolean inFinding = false, isFalsePositive = false;

        List<DataFlowElement> currentDataFlowElements = list();

        void addFinding() {

            currentRawFinding.append(currentQueryEndTag);

            findingMap.put(FindingKey.PATH, currentFileName);
            findingMap.put(FindingKey.PARAMETER, null);
            findingMap.put(FindingKey.VULN_CODE, currentVulnName);
            findingMap.put(FindingKey.SEVERITY_CODE, currentSeverity);
            findingMap.put(FindingKey.CWE, currentCweId);
            findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

            // TODO maybe parse parameter
            Finding finding = constructFinding(findingMap);

            if (finding != null) {
                finding.setSourceFileLocation(currentFileName);
                finding.setMarkedFalsePositive(isFalsePositive);

                finding.setEntryPointLineNumber(IntegerUtils.getPrimitive(findingLineNumber));
                finding.setNativeId(md5(currentUrlReference));
                finding.setUrlReference(currentUrlReference);
                finding.setIsStatic(true);
                finding.setDataFlowElements(currentDataFlowElements);
                saxFindingList.add(finding);
            }

            currentSequence = 1;
            currentFileName = null;
            findingLineNumber = null;
            currentUrlReference = null;
            isFalsePositive = false;
            currentDataFlowElements = list();
            inFinding = false;
            currentRawFinding.setLength(0);
        }

        void addDataFlowElement() {
            DataFlowElement element = new DataFlowElement();
            element.setLineNumber(IntegerUtils.getPrimitive(lineNumber));
            element.setLineText(StringEscapeUtils.unescapeXml(lineText));
            element.setSourceFileName(fileName);
            element.setSequence(currentSequence++); // ++ in use!
            currentDataFlowElements.add(element);
            lineText = lineNumber = null;
        }

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void startElement (String uri, String name,
                                  String qName, Attributes atts) {

            // Since we're two lines shorter I think if/else works better here
            if (qName.equals(ROOT_NODE_NAME)) {
                date = parseDate(atts.getValue(SCAN_START));

            } else if (qName.equals(QUERY)) {
                currentCweId = atts.getValue(CWE_ID);
                currentVulnName = atts.getValue(NAME_ATTRIBUTE);
                currentSeverity = atts.getValue(SEVERITY);
                currentQueryBeginTag = makeTag(name, qName, atts);
                currentQueryEndTag = "</" + qName + ">";

            } else if (qName.equals(RESULT)) {
                currentFileName = atts.getValue(FILE_NAME);
                findingLineNumber = atts.getValue(LINE);
                currentUrlReference = atts.getValue(URL);
                isFalsePositive = "True".equals(atts.getValue(FALSE_POSITIVE));
                inFinding = true;
                currentRawFinding.append(currentQueryBeginTag);

            } else if (qName.equals(LINE) || qName.equals(CODE) || qName.equals(FILE_NAME) || qName.equals(NAME)) {
                getText = true;

            } else if (qName.equals(NUMBER)) {
                getText = false;
                builder.setLength(0);
            }
            if (inFinding)
                currentRawFinding.append(makeTag(name, qName , atts));
        }

        public void endElement (String uri, String name, String qName) {
            if (getText) {
                if (qName.equals(LINE)) {
                    lineNumber = getBuilderText();
                } else if (qName.equals(CODE)) {
                    lineText = getBuilderText();
                } else if (qName.equals(FILE_NAME)) {
                    fileName = getBuilderText();
                } else if (qName.equals(NAME)) {
                    lineText = getBuilderText();
                }
                getText = false;
            } else {
                if (qName.equals(PATH_NODE)) {
                    addDataFlowElement();
                } else if (qName.equals(RESULT)) {
                    currentRawFinding.append("</").append(qName).append(">");
                    addFinding();
                }
            }
            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }

            if (qName.equalsIgnoreCase(QUERY)) {
                currentQueryBeginTag = null;
                currentQueryEndTag = null;
            }
        }

        public void characters (char[] ch, int start, int length) {
            if (getText) {
                addTextToBuilder(ch, start, length);
            }
            if (inFinding)
                currentRawFinding.append(ch,start,length);
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
        return testSAXInput(new CheckMarxScanValidator());
    }

    public class CheckMarxScanValidator extends DefaultHandler {
        private boolean hasFindings = false;
        private boolean hasDate = false;
        private boolean correctFormat = false;

        private void setTestStatus() {
            if (!correctFormat)
                testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
            else if (hasDate)
                testStatus = checkTestDate();
            if (testStatus == null)
                testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
        }

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void endDocument() {
            setTestStatus();
        }

        public void startElement (String uri, String name, String qName, Attributes atts)
                throws SAXException {
            if (ROOT_NODE_NAME.equals(qName)) {
                testDate = parseDate(atts.getValue(SCAN_START));
                hasDate = testDate != null;
                correctFormat = true;

                log.info("CheckMarx scan is from version " + atts.getValue(VERSION_ATTRIBUTE));
            }

            if (RESULT.equals(qName)) {
                hasFindings = true;
                setTestStatus();
                throw new SAXException(FILE_CHECK_COMPLETED);
            }
        }
    }

    private Calendar parseDate(String dateString) {
        Calendar date = DateUtils.getCalendarFromString(format_EEEE, dateString);
        return date != null? date : DateUtils.getCalendarFromString(format, dateString);
    }
}