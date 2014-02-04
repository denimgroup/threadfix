////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
//
//     The contents of this fileName are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this fileName except in
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

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.interop.ScanCheckResultBean;
import com.denimgroup.threadfix.importer.interop.ScanImportStatus;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 *
 * @author mcollins
 *
 */
class CheckMarxChannelImporter extends AbstractChannelImporter {

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
            CODE = "Code";

    // sample is                                                 17-Dec-2013 10:39
    static final SimpleDateFormat format = new SimpleDateFormat("dd-MMM-yyyy HH:mm", Locale.US);

    public CheckMarxChannelImporter() {
        super(ScannerType.CHECKMARX);
    }

    @Override
    public Scan parseInput() {
        return parseSAXInput(new CheckMarxScanParser());
    }

    public class CheckMarxScanParser extends HandlerWithBuilder {

        // These are per-Query
        String currentCweId = null,
            currentVulnName = null,
            currentSeverity = null;

        // These are per-Result
        String currentFileName = null,
            findingLineNumber = null;

        // These are per-PathNode
        String lineText = null,
            lineNumber = null,
            fileName = null;

        boolean getText = false;
        int currentSequence = 1;

        List<DataFlowElement> currentDataFlowElements = new ArrayList<>();

        void addFinding() {

            // TODO maybe parse parameter
            Finding finding = constructFinding(currentFileName, null, currentVulnName, currentSeverity, currentCweId);

            if (finding != null) {
                finding.setSourceFileLocation(currentFileName);

                finding.setEntryPointLineNumber(IntegerUtils.getPrimitive(findingLineNumber));
                finding.setNativeId(getNativeId(finding));
                finding.setIsStatic(true);
                finding.setDataFlowElements(currentDataFlowElements);
                saxFindingList.add(finding);
            }

            currentSequence = 1;
            currentFileName = null;
            findingLineNumber = null;
            currentDataFlowElements = new ArrayList<>();
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
                date = DateUtils.getCalendarFromString(format, atts.getValue(SCAN_START));

            } else if (qName.equals(QUERY)) {
                currentCweId = atts.getValue(CWE_ID);
                currentVulnName = atts.getValue(NAME_ATTRIBUTE);
                currentSeverity = atts.getValue(SEVERITY);

            } else if (qName.equals(RESULT)) {
                currentFileName = atts.getValue(FILE_NAME);
                findingLineNumber = atts.getValue(LINE);

            } else if (qName.equals(LINE) || qName.equals(CODE) || qName.equals(FILE_NAME) || qName.equals(NAME)) {
                getText = true;

            } else if (qName.equals(NUMBER)) {
                getText = false;
                builder.setLength(0);
            }
        }

        public void endElement (String uri, String name, String qName) {
            if (getText) {
                switch (qName) {
                    case LINE:      lineNumber = getBuilderText(); break;
                    case CODE:      lineText   = getBuilderText(); break;
                    case FILE_NAME: fileName   = getBuilderText(); break;
                    case NAME:      lineText   = getBuilderText(); break;
                }
                getText = false;
            } else {
                switch (qName) {
                    case PATH_NODE: addDataFlowElement(); break;
                    case RESULT:    addFinding();         break;
                }
            }
        }

        public void characters (char[] ch, int start, int length) {
            if (getText) {
                addTextToBuilder(ch, start, length);
            }
        }
    }

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
            if (ScanImportStatus.SUCCESSFUL_SCAN == testStatus && !hasFindings)
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

        public void startElement (String uri, String name, String qName, Attributes atts)
                throws SAXException {
            if (ROOT_NODE_NAME.equals(qName)) {
                testDate = DateUtils.getCalendarFromString(format, atts.getValue(SCAN_START));
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
}