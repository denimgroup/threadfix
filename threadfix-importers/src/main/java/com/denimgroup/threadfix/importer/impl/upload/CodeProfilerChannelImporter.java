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

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.map;

@ScanImporter(
        scannerName = "CodeProfiler", // This name must match the name in the CSV file
        format = ScanFormat.XML,
        startingXMLTags = { "scenario", "pkg-ok", "package" } // this is used when determining the scan type
)
public class CodeProfilerChannelImporter extends AbstractChannelImporter {
    private static final Pattern re_path = Pattern.compile("([^:]+):\\s*([^,]+),?\\s*");

    // public 0-arg constructor is mandatory so we can instantiate by reflection

    public CodeProfilerChannelImporter() {
        super("CodeProfiler");
    }

    public class Handler extends DefaultHandler {
        private final Map<Integer, Map<FindingKey, String>> testcases = map();
        private Map<FindingKey, String> currentFinding = null;
        private Map<FindingKey, String> currentTestcase = null;
        private String currentPU = null;
        private ArrayList<DataFlowElement> dataFlowElements = null;
        private int testcaseID = -1;
        private int lastline = -1;
        private ChannelSeverity severity = null;
        private final ArrayList<CPFinding> findings = new ArrayList<CPFinding>();

        private boolean recordCharacters;
        private final StringBuilder builder = new StringBuilder();

        public List<Finding> getFindings() {
            return null;

        }

        @Override
        public void startElement(final String uri, final String localName, final String qName,
                                 final Attributes attributes) throws SAXException {
            if (qName.equals("finding")) {
                currentFinding = map();
                currentPU = null;
                currentFinding.putAll(currentTestcase);
                dataFlowElements = new ArrayList<DataFlowElement>();
                currentFinding.put(FindingKey.NATIVE_ID, attributes.getValue("fid"));
                final int impact = Integer.valueOf(attributes.getValue("impact"));
                final int probability = Integer.valueOf(attributes.getValue("prb"));
                severity = channelSeverityDao.retrieveById(calculateSeverityCode(impact, probability));
                lastline = -1;

            } else if (qName.equals("pu")) {
                if (currentFinding == null) {
                    return;
                }
                if (currentPU == null) {
                    currentPU = attributes.getValue("loc");
                    currentFinding.put(FindingKey.PATH, parsePath(currentPU));
                } else {
                    currentPU = attributes.getValue("loc");
                        /* do not set anything */
                }

            } else if (qName.equals("testcase")) {
                currentTestcase = map();
                testcaseID = Integer.valueOf(attributes.getValue("id"));
                testcases.put(testcaseID, currentTestcase);
                currentTestcase.put(FindingKey.SEVERITY_CODE, "Information");
                currentTestcase.put(FindingKey.VULN_CODE, attributes.getValue("name"));

            } else if (qName.equals("ln")) {
                if (dataFlowElements == null) {
                    return;
                }
                try {
                    final DataFlowElement element = new DataFlowElement();
                    final String lineNoS = attributes.getValue("line");
                    Integer lineNo = (lineNoS == null || "".equals(lineNoS)) ? null : Integer.valueOf(lineNoS);
                    if (lineNo == null) {
                        lineNo = lastline;
                    }
                    lastline = lineNo + 1;
                    element.setLineNumber(lineNo);
                    element.setLineText(attributes.getValue("sc"));
                    element.setSourceFileName(currentPU);
                    dataFlowElements.add(element);
                } catch (Throwable t) {
                    t.printStackTrace();
                }

            } else if (qName.equals("intro") || qName.equals("risk") || qName.equals("detail")) {
                record();

            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {
            if (qName.equals("finding")) {
                final CPFinding finding = new CPFinding(currentFinding, dataFlowElements, testcaseID, severity);
                dataFlowElements = null;
                currentFinding = null;
                findings.add(finding);

            } else if (qName.equals("intro")) {
                final Map<FindingKey, String> testcase = testcases.get(testcaseID);
                if (testcase == null) {
                    throw new IllegalStateException("Invalid XML file");
                }
                testcase.put(FindingKey.DETAIL, getCharacters());

            } else if (qName.equals("risk") || qName.equals("detail")) {
                final Map<FindingKey, String> testcase = testcases.get(testcaseID);
                if (testcase == null) {
                    throw new IllegalStateException("Invalid XML file");
                }
                testcase.put(FindingKey.DETAIL, getCharacters());
                testcases.get(testcaseID).put(FindingKey.DETAIL, currentTestcase.get(FindingKey.DETAIL) +
                        "\n\n" + getCharacters());

            } else if (qName.equals("scenario")) {
                for (final CPFinding cpfinding : findings) {
                    saxFindingList.add(cpfinding.getFinding(testcases));
                }

            }
        }

        protected void record() {
            if (builder.length() != 0) {
                throw new IllegalStateException("Illegally formed XML file.");
            }
            recordCharacters = true;
        }

        protected String getCharacters() {
            recordCharacters = false;
            final String characters = builder.toString();
            builder.setLength(0);
            return characters;
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            super.characters(ch, start, length);
            if (recordCharacters) {
                builder.append(ch, start, length);
            }
        }
    }

    public static int calculateSeverityCode(final int impact, final int probability) {
        if (impact < 0 || impact > 4) {
            throw new IllegalArgumentException("0 <= impact <= 4 condition violated");
        }
        final int probStep = probability / 25;
        if (probStep < 0 || probStep > 4) {
            throw new IllegalArgumentException("0 <= probability <= 100 condition violated");
        }
        if (probStep < impact) {
            return probStep + 1;
        }
        return impact + 1;
    }

    public static String parsePath(final String path) {
        return path;
    }


    @Nullable
    @Override
    public Scan parseInput() {
        final Handler handler = new Handler();
        final Scan scan = parseSAXInput(handler);
        return scan;
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {
        return new ScanCheckResultBean(ScanImportStatus.SUCCESSFUL_SCAN, Calendar.getInstance());
    }

    public class CPFinding {
        private final Map<FindingKey, String> findingProperties;
        private final List<DataFlowElement> dataflow;
        private final int testcaseID;
        private final ChannelSeverity severity;

        public CPFinding(final Map<FindingKey, String> findingProperties, final List<DataFlowElement> dataflow,
                         final int testcaseID, final ChannelSeverity severity) {
            this.findingProperties = findingProperties;
            this.dataflow = dataflow;
            this.testcaseID = testcaseID;
            this.severity = severity;
        }

        public Finding getFinding(final Map<Integer, Map<FindingKey, String>> testcaseInfos) {
            findingProperties.putAll(testcaseInfos.get(testcaseID));
            final Finding finding = constructFinding(findingProperties);
            // be careful, constructFinding can return null if not given enough information
            if (finding == null) {
                throw new IllegalStateException("XML was invalid or we didn't parse out enough information");
            }

            finding.setIsStatic(true);

            // Add data flow
            finding.setDataFlowElements(dataflow);
            finding.setNativeId(findingProperties.get(FindingKey.NATIVE_ID));
            finding.setChannelSeverity(severity);

            // Potentially add other parameters

            return finding;
        }

    }
}
