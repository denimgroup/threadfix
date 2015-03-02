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

import com.denimgroup.threadfix.annotations.ScanFormat;
import com.denimgroup.threadfix.annotations.ScanImporter;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.impl.AbstractChannelImporter;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import org.xml.sax.Attributes;

import javax.annotation.Nonnull;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by mcollins on 3/2/15.
 */
@ScanImporter(
        // must match value in sample.csv
        scannerName="Scanner Name",
        // tell ThreadFix how to identify the scan file
        format = ScanFormat.XML,
        // these are the first tags a SAX parser will find (depth-first search)
        startingXMLTags = { "SampleScanFile", "Vulnerabilities" }
        // there are other properties for JSON + zip, consult the @ScanImporter annotation for more
)
public class SampleImporter extends AbstractChannelImporter {

    // public 0-arg constructor is mandatory so we can instantiate by reflection
    public SampleImporter() {
        super("Scanner Name");
    }

    @Override
    public Scan parseInput() {
        // this is a helper to deal with parsing the input file with a sax parser
        return parseSAXInput(new SampleScanSAXParser());
    }

    /**
     * This parser parses the following XML:
     *
     <SampleScanFile>
         <Vulnerabilities>
             <Vulnerability>
                 <Path>login.jsp</Path>
                 <Parameter>username</Parameter>
                 <Type>XSS</Type>
                 <Severity>High</Severity>
             </Vulnerability>
         </Vulnerabilities>
     </SampleScanFile>
     *
     *
     */
    public class SampleScanSAXParser extends HandlerWithBuilder {

        private FindingKey currentKey = null;
        private Map<FindingKey, String> findingMap = new HashMap<>();

        // we need to add the finding to the saxFindingList field
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

        @Override
        public void startElement(String uri, String name,
                                 String qName, Attributes atts) {

            // set the current key so we can retrieve the tag's text
            switch (qName) {
                case "Path":      currentKey = FindingKey.PATH;          break;
                case "Parameter": currentKey = FindingKey.PARAMETER;     break;
                case "Type":      currentKey = FindingKey.VULN_CODE;     break;
                case "Severity":  currentKey = FindingKey.SEVERITY_CODE; break;
            }
        }

        @Override
        public void endElement(String uri, String name, String qName) {
            if (qName.equals("Vulnerability")) {
                // we should have all the information. This creates a Finding from the map and puts it in the scan.
                Finding finding = constructFinding(findingMap);
                add(finding);
            } else if (currentKey != null) {
                // getBuilderText retrieves the text from the builder.
                // this should contain any text in the tag associated with the key
                findingMap.put(currentKey, getBuilderText());
                currentKey = null;
            }

        }

        @Override
        public void characters (char ch[], int start, int length) {
            if (currentKey != null) { // if we're in an element that we should record, add the text between tags to the builder
                addTextToBuilder(ch, start, length);
            }
        }
    }

    @Nonnull
    @Override
    public ScanCheckResultBean checkFile() {

        // Do checks to determine the correct ScanImportStatus to return
        // this is where duplicate scan checking happens
        // the Calendar should be the scan date

        return new ScanCheckResultBean(ScanImportStatus.SUCCESSFUL_SCAN, Calendar.getInstance());
    }


}
