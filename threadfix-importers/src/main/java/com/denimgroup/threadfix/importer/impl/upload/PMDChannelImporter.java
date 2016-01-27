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
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mhatzenbuehler on 7/3/2014.
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.PMD_DB_NAME,
        startingXMLTags = "pmd"
)
public class PMDChannelImporter extends AbstractChannelImporter {
    public PMDChannelImporter() {
        super(ScannerType.PMD);
    }

    @Override
    @Transactional
    public Scan parseInput() {
        Scan returnScan = parseSAXInput(new PmdSAXParser());
        return returnScan;
    }

    public class PmdSAXParser extends HandlerWithBuilder {
        Map<FindingKey, String> findingMap = map();

        private Boolean inSecurityBug         = false;
        private Boolean getDataFlowElements   = false;

        private String currentChannelVulnCode = null;
        private String currentPath            = null;
        private String currentParameter       = null;
        private String currentSeverityCode    = null;
        private StringBuffer currentRawFinding	  = new StringBuffer();

        private List<DataFlowElement> dataFlowElements = null;
        private int dataFlowPosition;

        public void add(Finding finding) {
            if (finding != null) {
                finding.setNativeId(getNativeId(finding));
                finding.setIsStatic(true);
                finding.setSourceFileLocation(currentPath);
                saxFindingList.add(finding);
            }
        }

        public DataFlowElement getDataFlowElement (Attributes atts, int position) {
            String start = atts.getValue("beginline");
            String path = currentPath;
            Integer lineNum = null;

            if (start != null) {
                try {
                    lineNum = Integer.valueOf(start);
                } catch (NumberFormatException e) {
                    log.error("PMD had a non-integer value in its begin line number field");
                }
            }

            if (lineNum == null) {
                lineNum = -1;
            }

            return new DataFlowElement(path, lineNum, atts.getValue("name"), position);
        }

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void startElement (String uri, String name,
                                  String qName, Attributes atts) {
            if ("file".equals(qName)) {
                currentPath = atts.getValue("name");
            }

            if ("violation".equals(qName) && "Security Code Guidelines".equals(atts.getValue("ruleset"))) {
                inSecurityBug = true;
                currentChannelVulnCode = atts.getValue("rule");
                currentSeverityCode = atts.getValue("priority");

                if(atts.getValue("variable") != null) {
                    currentParameter = atts.getValue("variable");
                } else {
                    currentParameter = atts.getValue("method");
                }

                getDataFlowElements = true;
                dataFlowElements = new LinkedList<DataFlowElement>();
                dataFlowElements.add(getDataFlowElement(atts,0));
                dataFlowPosition = 1;
            }

            if (inSecurityBug) {
                currentRawFinding.append(makeTag(name, qName, atts));
            }
        }

        public void endElement (String uri, String name, String qName) {
            if (inSecurityBug) {
                findingMap.put(FindingKey.PATH, currentPath);
                findingMap.put(FindingKey.PARAMETER, currentParameter);
                findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
                findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

                Finding finding = constructFinding(findingMap);

                if (finding != null) {
                    finding.setDataFlowElements(dataFlowElements);
                    finding.setSourceFileLocation(currentPath);
                    add(finding);
                }

                inSecurityBug = false;
                currentParameter = null;
                currentChannelVulnCode = null;
                currentSeverityCode = null;
                dataFlowElements = null;
                dataFlowPosition = 0;
                getDataFlowElements = false;
                currentRawFinding.setLength(0);
            }
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
        return testSAXInput(new PmdSAXValidator());
    }

    public class PmdSAXValidator extends DefaultHandler {
        private boolean hasFindings = false;
        private boolean hasDate = false;
        private boolean correctFormat = false;

        private void setTestStatus() {
            if (!correctFormat) {
                testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
            } else if (hasDate) {
                testStatus = checkTestDate();
            }

            if (testStatus == null) {
                testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
            }
        }

        private Calendar parseTimestamp(String dateTimeString) {
            String dateFormat = "yyyy-MM-dd'T'kk:mm:ss.SSS";

            Calendar cal = Calendar.getInstance();
            SimpleDateFormat sdf = new SimpleDateFormat(dateFormat, Locale.US);
            try {
                cal.setTime(sdf.parse(dateTimeString));
            } catch (ParseException e) {
                e.printStackTrace();
            }

            return cal;
        }

        public void endDocument() {
            setTestStatus();
        }

        public void startElement(String uri, String name, String qName, Attributes atts) throws SAXException {
            if("pmd".equals(qName)) {
                testDate = parseTimestamp(atts.getValue("timestamp"));
                hasDate = testDate != null;
                correctFormat = true;
            } else if("violation".equals(qName)) {
                hasFindings = true;
                setTestStatus();
                throw new SAXException(FILE_CHECK_COMPLETED);
            }
        }
    }
}
