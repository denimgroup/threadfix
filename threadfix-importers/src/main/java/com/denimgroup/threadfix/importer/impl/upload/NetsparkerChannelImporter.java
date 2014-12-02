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
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.annotation.Nonnull;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author mcollins
 *
 */
@ScanImporter(
        scannerName = ScannerDatabaseNames.NETSPARKER_DB_NAME,
        startingXMLTags = "netsparker"
)
public class NetsparkerChannelImporter extends AbstractChannelImporter {

    public NetsparkerChannelImporter() {
        super(ScannerType.NETSPARKER);
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.denimgroup.threadfix.service.channel.ChannelImporter#parseInput()
     */
    @Override
    public Scan parseInput() {
        return parseSAXInput(new NetsparkerSAXParser());
    }

    public class NetsparkerSAXParser extends HandlerWithBuilder {
        private boolean getChannelVulnText    = false;
        private boolean getUrlText            = false;
        private boolean getParamText          = false;
        private boolean getSeverityText       = false;
        private boolean getParamValueText	  = false;
        private boolean getRequestText		  = false;
        private boolean getResponseText       = false;
        private boolean getDescriptionText	  = false;
        private boolean getCweText			  = false;
        private boolean inFinding		  = false;

        private StringBuffer currentRawFinding	  = new StringBuffer();
        private String currentChannelVulnCode = null;
        private String currentUrlText         = null;
        private String currentParameter       = null;
        private String currentSeverityCode    = null;
        private String currentParameterValue  = null;
        private String currentRequest         = null;
        private String currentResponse        = null;
        private String currentDescription	  = null;
        private String currentCwe			  = null;
        private String host = null;

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
                                  String qName, Attributes atts)
        {
            if ("type".equals(qName)) {
                getChannelVulnText = true;
                getBuilderText(); //resets the stringbuffer
            } else if ("url".equals(qName)) {
                getUrlText = true;
                getBuilderText();
            } else if ("vulnerableparameter".equals(qName)) {
                getParamText = true;
                getBuilderText(); //resets the stringbuffer
            } else if ("severity".equals(qName)) {
                getSeverityText = true;
                getBuilderText(); //resets the stringbuffer
            } else if("vulnerableparametervalue".equals(qName)){
                getParamValueText = true;
                getBuilderText(); //resets the stringbuffer
            } else if("rawrequest".equals(qName)){
                getRequestText = true;
                getBuilderText(); //resets the stringbuffer
            } else if("rawresponse".equals(qName)){
                getResponseText = true;
                getBuilderText(); //resets the stringbuffer
            } else if("description".equals(qName)){
                getDescriptionText = true;
                getBuilderText(); //resets the stringbuffer
            } else if("CWE".equals(qName)){
                getCweText = true;
                getBuilderText(); //resets the stringbuffer
            } else if ("netsparker".equals(qName)) {
//	    		date = getCalendarFromString("MM/dd/yyyy hh:mm:ss a", atts.getValue("generated"));
                date = getCalendar(atts.getValue("generated"));
            } else if ("vulnerability".equals(qName)){
                inFinding = true;
            }
            // in a finding, build the tag
            if (inFinding){
                currentRawFinding.append(makeTag(name, qName , atts));
            }

        }

        public void endElement (String uri, String name, String qName)
        {
            if (getChannelVulnText) {
                currentChannelVulnCode = getBuilderText();
                getChannelVulnText = false;
            } else if (getUrlText) {
                if (host == null)
                    host = getBuilderText();
                else
                    currentUrlText = getBuilderText();
                getUrlText = false;
            } else if (getParamText) {
                currentParameter = getBuilderText();
                getParamText = false;
            } else if (getParamValueText) {
                currentParameterValue = getBuilderText();
                getParamValueText = false;
            } else if (getRequestText) {
                currentRequest = getBuilderText();
                getRequestText = false;
            } else if (getResponseText) {
                currentResponse = getBuilderText();
                getResponseText = false;
            } else if (getDescriptionText) {
                currentDescription = getBuilderText();
                getDescriptionText = false;
            } else if (getCweText) {
                currentCwe = getBuilderText();
                getCweText = false;
            } else if (getSeverityText) {
                currentSeverityCode = getBuilderText();
                getSeverityText = false;
            }
            if (inFinding){
                currentRawFinding.append("</").append(qName).append(">");
            }

            if ("vulnerability".equals(qName)) {

                Map<FindingKey, String> findingMap = new HashMap<>();
                findingMap.put(FindingKey.PATH, currentUrlText);
                findingMap.put(FindingKey.PARAMETER, currentParameter);
                findingMap.put(FindingKey.VULN_CODE, currentChannelVulnCode);
                findingMap.put(FindingKey.SEVERITY_CODE, currentSeverityCode);
                findingMap.put(FindingKey.CWE, currentCwe);
                findingMap.put(FindingKey.VALUE, currentParameterValue);
                findingMap.put(FindingKey.REQUEST, currentRequest);
                findingMap.put(FindingKey.RESPONSE, currentResponse);
                findingMap.put(FindingKey.DETAIL, currentDescription);
                findingMap.put(FindingKey.RECOMMENDATION, null);
                findingMap.put(FindingKey.RAWFINDING, currentRawFinding.toString());

                Finding finding = constructFinding(findingMap);

                // The old XML format didn't include severities. As severities are required
                // for vulnerabilities to show on the application page, let's assign medium
                // severity. This is only known to affect beta versions of Netsparker.
                if (finding != null && finding.getChannelSeverity() == null) {
                    ChannelSeverity mediumChannelSeverity = channelSeverityDao.retrieveByCode(channelType, "Medium");
                    finding.setChannelSeverity(mediumChannelSeverity);
                }

                add(finding);

                currentChannelVulnCode = null;
                currentSeverityCode    = null;
                currentParameter       = null;
                currentUrlText         = null;
                currentParameterValue  = null;
                currentRequest         = null;
                currentResponse        = null;
                currentDescription     = null;
                currentCwe 			   = null;
                inFinding 			   = false;
                currentRawFinding.setLength(0);
            }
        }

        public void characters (char ch[], int start, int length)
        {
            if (getCweText || getChannelVulnText || getUrlText || getParamText || getSeverityText || getParamValueText || getRequestText || getResponseText || getDescriptionText) {
                addTextToBuilder(ch, start, length);
            }
            if (inFinding)
                currentRawFinding.append(ch,start,length);
        }
    }

    @Override
    public ScanCheckResultBean checkFile() {
        return testSAXInput(new NetsparkerSAXValidator());
    }

    public class NetsparkerSAXValidator extends DefaultHandler {
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

	    public void startElement (String uri, String name, String qName, Attributes atts) throws SAXException {
	    	if ("netsparker".equals(qName)) {
                testDate = getCalendar(atts.getValue("generated"));
                if (testDate != null)
                    hasDate = true;
                correctFormat = true;
            }

            if ("vulnerability".equals(qName)) {
                hasFindings = true;
                setTestStatus();
                throw new SAXException(FILE_CHECK_COMPLETED);
            }
        }
    }

    private Calendar getCalendar(String dateString) {
        Calendar result = null;
        result = DateUtils.getCalendarFromString("MM/dd/yyyy hh:mm:ss a", dateString);
        if (result == null)
            result = DateUtils.getCalendarFromString("dd/MM/yyyy hh:mm:ss", dateString);
        return result;
    }
}
