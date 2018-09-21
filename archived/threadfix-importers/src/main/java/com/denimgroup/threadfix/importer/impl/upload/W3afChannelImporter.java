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
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Imports the results of a W3AF scan (xml output).
 * 
 * The only information tags it currently handles are the "Interesting file" ones.
 * 
 * @author mcollins
 */
@ScanImporter(scannerName = ScannerDatabaseNames.W3AF_DB_NAME,
            startingXMLTagSets = {@StartingTagSet("w3afrun"), @StartingTagSet("w3af-run") })
public class W3afChannelImporter extends AbstractChannelImporter {

    public static final String POTENTIALLY_INTERESTING_FILE = "Potentially interesting file";
    private final       String dateFormatString             = "EEE MMM dd HH:mm:ss yyyy";

    public W3afChannelImporter() {
        super(ScannerType.W3AF);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
     */
    @Override
    public Scan parseInput() {
        return parseSAXInput(new W3afSAXParser());
    }

    /*
     * This method takes the name of a tag as a parameter and then replaces the inputStream object
     * with a new InputStream that does not include any of those tags.
     *
     *  The start tag must start with the text <tagName and the end tag must be </tagName>.
     *
     *  This method could be adapted to take out any of a list of tags and is fairly generic.
     *
     * @param tagName
     * @throws IOException
     */
    private void removeTagFromInputStream(String tagName) throws IOException {
        if (inputStream == null)
            return;

        String startTag = "<" + tagName, endTag = "</" + tagName + ">";

        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder contents = new StringBuilder();

        String inputValue = reader.readLine();

        boolean inResponseTag = false;

        while (inputValue != null) {

            if (inputValue.contains(startTag)) {
                if (inputValue.contains(endTag)) {
                    inputValue = inputValue.substring(0, inputValue.indexOf(startTag)) +
                            inputValue.substring(inputValue.indexOf(endTag) + endTag.length());
                } else {
                    inResponseTag = true;
                    inputValue = inputValue.substring(0, inputValue.indexOf(startTag));
                    contents.append(inputValue);
                }
            }

            if (inResponseTag && inputValue.contains(endTag)) {
                inResponseTag = false;
                inputValue = inputValue.substring(inputValue.indexOf(endTag) + endTag.length());
            }

            if (!inResponseTag) {
                contents.append(inputValue);
            }

            inputValue = reader.readLine();
        }
        closeInputStream(inputStream);
        inputStream = new ByteArrayInputStream(contents.toString().getBytes("UTF-8"));
    }

    public class W3afSAXParser extends HandlerWithBuilder {

        private StringBuffer currentRawFinding = new StringBuffer();
        private StringBuffer currentRequest = new StringBuffer();
        private StringBuffer currentResponse = new StringBuffer();
        private Map<FindingKey, String> findingMap = map();
        private Boolean inVuln = false;
        private String path, param, vuln, severity;
        private String description = null,
                detailDescription = null,
                fixGuidance = null;
        private boolean getText = false, inRequest, inResponse;



        private void addFinding() {
            findingMap.put(FindingKey.PATH, path);
            findingMap.put(FindingKey.PARAMETER, param);
            findingMap.put(FindingKey.VULN_CODE, vuln);
            findingMap.put(FindingKey.SEVERITY_CODE, severity);
            findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());
            findingMap.put(FindingKey.RECOMMENDATION, fixGuidance);
            findingMap.put(FindingKey.DETAIL, detailDescription);
            findingMap.put(FindingKey.REQUEST, currentRequest.toString());
            findingMap.put(FindingKey.RESPONSE, currentResponse.toString());

            Finding finding = constructFinding(findingMap);

            if (finding != null) {
                finding.setLongDescription(description);
                finding.setNativeId(getNativeId(finding));
                finding.setIsStatic(false);
                saxFindingList.add(finding);
            }
        }

        ////////////////////////////////////////////////////////////////////
        // Event handlers.
        ////////////////////////////////////////////////////////////////////

        public void startElement(String uri, String name, String qName, Attributes atts) {
            if ("w3afrun".equals(qName))
                date = DateUtils.getCalendarFromString(dateFormatString, atts.getValue("startstr"));
            if ("w3af-run".equals(qName))
                date = DateUtils.getCalendarFromString(dateFormatString, atts.getValue("start-long"));

            if ("vulnerability".equals(qName) && atts.getValue("url") != null &&
                    !atts.getValue("url").isEmpty()) {
                inVuln = true;

                param = atts.getValue("var");
                if ("None".equals(param))
                    param = null;

                path = atts.getValue("url");
                vuln = atts.getValue("name");
                severity = atts.getValue("severity");

            }

            if ("information".equals(qName) && POTENTIALLY_INTERESTING_FILE.equals(atts.getValue("name")) &&
                    atts.getValue("url") != null && !atts.getValue("url").isEmpty()) {
                inVuln = true;
                param = null;
                path = atts.getValue("url");
                vuln = atts.getValue("name");
                severity = "Info";
            }
            if ("description".equals(qName)) {
                description = null;
                getText = true;
            }
            else if ("long-description".equals(qName)) {
                detailDescription = null;
                getText = true;
            }
            else if ("fix-guidance".equals(qName)) {
                fixGuidance = null;
                getText = true;
            }
            else if ("httprequest".equals(qName)){
                if (currentRequest.toString().isEmpty()) {
                    inRequest = true;
                }
            }
            else if ("httpresponse".equals(qName) || "http-response".equals(qName)){
                if (currentResponse.toString().isEmpty()) {
                    inResponse = true;
                }
            }
            else {
                getText = false;
            }

            if (inVuln) {
                currentRawFinding.append(makeTag(name, qName , atts));
            }

            if (inRequest) {
                currentRequest.append(makeTag(name, qName , atts));
            }
            if (inResponse) {
                currentResponse.append(makeTag(name, qName , atts));
            }
        }

        public void endElement(String uri, String name, String qName) {
            if (inVuln) {
                currentRawFinding.append("</").append(qName).append(">");
            }

            if (inRequest) {
                currentRequest.append("</").append(qName).append(">");
            }
            if (inResponse) {
                currentResponse.append("</").append(qName).append(">");
            }

            if (inVuln
                    && "vulnerability".equals(qName)|"information".equals(qName)) {

                addFinding();

                inVuln = false;
                inRequest = false;
                inResponse = false;
                param = null;
                path = null;
                vuln = null;
                severity = null;
                currentRawFinding.setLength(0);
                currentRequest.setLength(0);
                currentResponse.setLength(0);

                description = null;
                detailDescription = null;
                fixGuidance = null;
            }

            if ("description".equals(qName)) {
                description = getBuilderText();
                getText = false;
            }
            if ("long-description".equals(qName)) {
                detailDescription = getBuilderText();
                getText = false;
            }
            if ("fix-guidance".equals(qName)) {
                fixGuidance = getBuilderText();
                getText = false;
            }
            if ("httprequest".equals(qName)){
                inRequest = false;
            }
            if ("httpresponse".equals(qName) || "http-response".equals(qName)){
                inResponse = false;
            }
        }

        public void characters (char ch[], int start, int length)
        {
            if (inVuln)
                currentRawFinding.append(ch,start,length);
            if (inRequest) {
                currentRequest.append(ch,start,length);
            }
            if (inResponse) {
                currentResponse.append(ch,start,length);
            }
            if (getText)
                addTextToBuilder(ch, start, length);
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {

        try {
            removeTagFromInputStream("httpresponse");
            removeTagFromInputStream("http-response");
        } catch (IOException e) {
            log.error("Encountered IOException while trying to remove the httpresponse tag in checkFile.", e);
        }

        return testSAXInput(new W3afSAXValidator());
    }

    public class W3afSAXValidator extends DefaultHandler {
        private boolean hasFindings = false, hasDate = false, correctFormat = false;

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

        public void startElement(String uri, String name, String qName, Attributes atts) {
            if ("vulnerability".equals(qName))
                hasFindings = true;

            if (!correctFormat && "w3afrun".equals(qName)) {
                correctFormat = true;
                testDate = DateUtils.getCalendarFromString(dateFormatString, atts.getValue("startstr"));
                hasDate = testDate != null;
            }

            if (!correctFormat && "w3af-run".equals(qName)) {
                correctFormat = true;
                testDate = DateUtils.getCalendarFromString(dateFormatString, atts.getValue("start-long"));
                hasDate = testDate != null;
            }

        }
    }
}
