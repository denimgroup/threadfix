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
package com.denimgroup.threadfix.csv2ssl.serializer;

import com.denimgroup.threadfix.csv2ssl.util.Strings;
import com.denimgroup.threadfix.csv2ssl.util.DateUtils;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import java.util.Map;

/**
 * Created by mac on 12/2/14.
 */
public class RecordToXMLSerializer {

    private RecordToXMLSerializer(){}

    public static String getFromReader(CSVParser parser) {
        StringBuilder builder = new StringBuilder("<?xml version=\"1.0\"?>\n" +
                "<Vulnerabilities SpecVersion=\"0.2\"\n" +
                "        ApplicationTag=\"Application Name\"\n" +
                "        ExportTimestamp=\"" + DateUtils.getCurrentTimestamp() + "\"\n" +
                "        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "        xsi:noNamespaceSchemaLocation=\"ssvl.xsd\">\n");

        int i = 0;
        for (CSVRecord strings : parser) {
            Map<String, String> map = strings.toMap();

            String nativeId = map.get(Strings.NATIVE_ID);

            if (nativeId == null || nativeId.isEmpty()) {
                System.out.println("Missing native ID for line " + i + ", no vulnerability created.");
                continue;
            }

            String sourceScanner = map.get(Strings.SOURCE);
            String severity = map.get(Strings.SEVERITY);
            String cweId = map.get(Strings.CWE);
            String urlString = map.get(Strings.URL);
            String issueId = map.get(Strings.ISSUE_ID);

            String parameterString = map.get(Strings.PARAMETER);
            parameterString = parameterString == null ? "" : parameterString;
            severity = severity == null || severity.trim().isEmpty() ? "Medium" : severity;

            String dateString = map.get(Strings.FINDING_DATE);

            if (cweId == null) {
                cweId = Strings.DEFAULT_CWE;
            }

            builder.append("\t<Vulnerability ")
                    .append("CWE=\"").append(cweId).append("\" ");

            if (issueId != null) {
                builder.append("IssueID=\"").append(issueId).append("\" ");
            }

            builder.append("Severity=\"").append(severity).append("\">\n");

            appendTagIfPresent(map, builder, "ShortDescription", Strings.SHORT_DESCRIPTION);
            appendTagIfPresent(map, builder, "LongDescription", Strings.LONG_DESCRIPTION);

            builder.append("\t\t<Finding NativeID=\"").append(nativeId).append("\" Source=\"").append(sourceScanner).append("\"");

            if (dateString != null) {
                String newDate = DateUtils.toOurFormat(dateString);
                builder.append(" IdentifiedTimestamp=\"").append(newDate).append("\"");
            }

            builder.append(">\n")
                    .append("\t\t\t<SurfaceLocation url=\"").append(urlString).append("\" source=\"Parameter\" value=\"").append(parameterString)
                    .append("\"/>\n\t\t</Finding>\n");

            builder.append("\t</Vulnerability>\n");
            i++;
        }

        builder.append("</Vulnerabilities>");

        return builder.toString();
    }

    private static void appendTagIfPresent(Map<String, String> map, StringBuilder builder, String name, String key) {
        String value = map.get(key);
        if (value != null) {
            builder.append("\t\t<").append(name).append(">\n\t\t\t")
                    .append(value).append("\n")
                    .append("\t\t</").append(name).append(">\n");
        }
    }

}
