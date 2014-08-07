package com.denimgroup.threadfix.importer.impl.upload;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.springframework.transaction.annotation.Transactional;
import org.xml.sax.Attributes;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by mhatzenbuehler on 8/4/2014.
 */
public class ClangChannelImporter extends AbstractChannelImporter {
    public ClangChannelImporter(){super(ScannerType.CLANG);}

    @Override
    @Transactional
    public Scan parseInput() {
        Scan returnScan = parseSAXInput(new ClangSAXParser());
        return returnScan;
    }

    public class ClangSAXParser extends HandlerWithBuilder {
        Map <FindingKey, String> findingMap = new HashMap<>();

        private Boolean inSecurityBug           = false;
        private Boolean getDataFlowElements     = false;

        private String currentChannelVulnCode   = null;
        private String currentPath              = null;
        private String currentParameter         = null;
        private String currentSeverityCode      = null;
        private StringBuffer currentRawFinding  = new StringBuffer();

        private List<DataFlowElement> dataFlowElements = null;
        private int dataFlowPosition;

        public void add(Finding finding) {
            if(finding != null) {
                finding.setNativeId(getNativeId(finding));
                finding.setIsStatic(true);
                finding.setSourceFileLocation(currentPath);
                saxFindingList.add(finding);
            }
        }

        public DataFlowElement getDataFlowElement(Attributes atts, int position) {
            String start = atts.getValue("beginline");
            String path = currentPath;
            Integer lineNum = null;

            if(start != null) {
                try {
                    lineNum = Integer.valueOf(start);
                } catch (NumberFormatException e) {
                    log.error("Clang had a non-integer value in its line number field");
                }
            }

            if(lineNum == null) {
                lineNum = -1;
            }

            return new DataFlowElement(path, lineNum, atts.getValue("name"), position);
        }

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void startElement (String uri, String name, String qName, Attributes atts) {
            //figure out what to parse here
            if("file".equals(qName)) {
                currentPath = atts.getValue("name");
            }
        }

        public void endElement(String uri, String name, String qName) {
            if(inSecurityBug) {
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
    public ScanCheckResultBean checkFile() {return testSAXInput(new ClangSAXValidator());}

    public class ClangSAXValidator extends DefaultHandler {
        //private boolean hasFindings = false;
        //private boolean hasDate = false;
        //private boolean correctFormat = false;

        private void setTestStatus() {

        }

//        private void setTestStatus() {
//            if(!correctFormat) {
//                testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
//            } else if (hasDate) {
//                testStatus = checkTestDate();
//            }
//
//            if((testStatus == null || ScanImportStatus.SUCCESSFUL_SCAN == testStatus) && !hasFindings) {
//                testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
//            } else if (testStatus == null){
//                testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
//            }
//        }
    }

}
