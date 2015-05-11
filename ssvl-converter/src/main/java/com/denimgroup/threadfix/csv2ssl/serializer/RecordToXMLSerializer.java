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
package com.denimgroup.threadfix.csv2ssl.serializer;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.util.DateUtils;
import com.denimgroup.threadfix.csv2ssl.util.Strings;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.util.Map;

import static com.denimgroup.threadfix.csv2ssl.util.CollectionUtils.map;
import static org.apache.commons.lang3.StringEscapeUtils.escapeXml;

/**
 * Created by mac on 12/2/14.
 */
public class RecordToXMLSerializer {

    private RecordToXMLSerializer(){}

    private static Map<String, String> severities = map(
            "1", "Info",
            "2", "Low",
            "3", "Medium",
            "4", "High",
            "5", "Critical"
    );

    public static String getFromExcel(XSSFWorkbook wb, String... format) {
        StringBuilder builder = getStart();

        int line = Configuration.CONFIG.shouldSkipFirstLine ? 1 : 0;

        XSSFSheet ws = wb.getSheetAt(0); // read the first sheet
        int totalColumns = ws.getRow(0).getLastCellNum();
        int totalRows = ws.getLastRowNum();
        Map<String, String> rowMap = map();

        for (; line <= totalRows; line++) { // we want <= because the index returned from ws.getLastRowNum() is valid
            XSSFRow row = ws.getRow(line);

            for (int column = 0; column < totalColumns; column++){
                XSSFCell cell = row.getCell(column);

                if (cell == null) {
                    // cells are null if there's no data in them; this is fine.
                    continue;
                }

                String value = cell.toString();

                if (format.length > column) {
                    rowMap.put(format[column], value);
                } else {
                    System.err.println("format wasn't long enough for column. Column length = " + totalColumns + ", format was " + format.length);
                }
            }

            addRecord(builder, line, rowMap);
            rowMap.clear();
        }

        return writeEnd(builder);
    }

    public static String getFromReader(CSVParser parser) {
        StringBuilder builder = getStart();

        int i = -1;
        for (CSVRecord strings : parser) {
            i++;
            addRecord(builder, i, strings.toMap());
        }

        return writeEnd(builder);
    }

    private static StringBuilder getStart() {
        return new StringBuilder("<?xml version=\"1.0\"?>\n" +
                "<Vulnerabilities SpecVersion=\"0.2\"\n" +
                "        ApplicationTag=\"Application Name\"\n" +
                "        ExportTimestamp=\"" + DateUtils.getCurrentTimestamp() + "\"\n" +
                "        xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
                "        xsi:noNamespaceSchemaLocation=\"ssvl.xsd\">\n");
    }

    private static String writeEnd(StringBuilder builder) {
        builder.append("</Vulnerabilities>");

        return builder.toString();
    }

    // TODO switch to a real XML library instead of using StringEscapeUtils.escapeXml
    // this code got really messy
    private static void addRecord(StringBuilder builder, int line, Map<String, String> map) {
        String nativeId = get(map, Strings.NATIVE_ID);

        if (nativeId == null || nativeId.isEmpty()) {
            System.out.println("Missing native ID for line " + line + ", no vulnerability created.");
            return;
        }

        String sourceScanner = get(map, Strings.SOURCE),
            sourceFileName = get(map, Strings.SOURCE_FILE_NAME),
            severity = get(map, Strings.SEVERITY),
            cweId = get(map, Strings.CWE),
            urlString = get(map, Strings.URL),
            issueId = get(map, Strings.ISSUE_ID);

        String parameterString = get(map, Strings.PARAMETER);
        parameterString = parameterString == null ? "" : parameterString;

        severity = severity == null || severity.trim().isEmpty() ? "Medium" : severity;
        if (severities.containsKey(severity.trim())) {
            severity = severities.get(severity.trim());
        }

        String dateString = get(map, Strings.FINDING_DATE);

        if (cweId == null || !cweId.matches("^[0-9]+$")) {
            System.out.println("Invalid CWE value found on line " + line + ", using the default CWE value (" + Strings.DEFAULT_CWE + ")");
            cweId = Strings.DEFAULT_CWE;
        }

        builder.append("\t<Vulnerability ")
                .append("CWE=\"").append(escapeXml(cweId)).append("\" ");

        if (issueId != null) {
            builder.append("IssueID=\"").append(escapeXml(issueId)).append("\" ");
        }

        builder.append("Severity=\"").append(escapeXml(severity)).append("\">\n");

        appendTagIfPresent(map, builder, "ShortDescription", Strings.SHORT_DESCRIPTION);
        appendTagIfPresent(map, builder, "LongDescription", Strings.LONG_DESCRIPTION);

        appendFindingStart(builder, nativeId, sourceScanner, sourceFileName, dateString);
        appendSurfaceLocation(builder, urlString, parameterString);
        appendDataFlowElements(builder, map);
        builder.append("\n\t\t</Finding>\n");

        builder.append("\t</Vulnerability>\n");
    }

    private static void appendFindingStart(StringBuilder builder, String nativeId, String sourceScanner, String sourceFileName, String dateString) {
        builder.append("\t\t<Finding NativeID=\"").append(escapeXml(nativeId)).append("\"");

        if (sourceScanner != null) {
            builder.append(" Source=\"").append(escapeXml(sourceScanner)).append("\"");
        }

        if (sourceFileName != null) {
            builder.append(" SourceFileName=\"").append(escapeXml(sourceFileName)).append("\"");
        }

        if (dateString != null) {
            String newDate = DateUtils.toOurFormat(dateString);
            if (newDate != null) {
                builder.append(" IdentifiedTimestamp=\"").append(escapeXml(newDate)).append("\"");
            }
        }

        builder.append(">");
    }

    private static void appendSurfaceLocation(StringBuilder builder, String urlString, String parameterString) {
        if (urlString != null || !parameterString.trim().equals("")) {
            builder.append("\n\t\t\t<SurfaceLocation url=\"").append(escapeXml(urlString)).append("\"");

            if (!"".equals(parameterString)) {
                builder.append(" source=\"Parameter\" value=\"").append(escapeXml(parameterString)).append("\"");
            }

            builder.append("/>");
        }
    }

    private static void appendDataFlowElements(StringBuilder builder, Map<String, String> map) {

        String sourceFileName = get(map, Strings.SOURCE_FILE_NAME),
                columnNumber = get(map, Strings.COLUMN_NUMBER),
                lineNumber = get(map, Strings.LINE_NUMBER),
                lineText = get(map, Strings.LINE_TEXT);

        if (columnNumber != null || lineNumber != null || lineText != null || sourceFileName != null) {
            builder.append("\n").append("\t\t\t<DataFlowElement");

            if (sourceFileName != null) {
                builder.append(" SourceFileName=\"").append(escapeXml(sourceFileName)).append("\"");
            }
            if (lineNumber != null) {
                builder.append(" LineNumber=\"").append(escapeXml(lineNumber)).append("\"");
            }
            if (columnNumber != null) {
                builder.append(" ColumnNumber=\"").append(escapeXml(columnNumber)).append("\"");
            }
            builder.append(">\n");

            lineText = lineText == null ? "" : lineText;
            builder.append("\t\t\t\t<LineText>\n\t\t\t\t\t")
                    .append(escapeXml(lineText))
                    .append("\n\t\t\t\t</LineText>\n");

            builder.append("\t\t\t</DataFlowElement>");
        }
    }

    private static void appendTagIfPresent(Map<String, String> map, StringBuilder builder, String name, String key) {
        String value = get(map, key);
        if (value != null && !"".equals(value.trim())) {
            builder.append("\t\t<").append(escapeXml(name)).append(">\n\t\t\t")
                    .append(escapeXml(value)).append("\n")
                    .append("\t\t</").append(escapeXml(name)).append(">\n");
        }
    }

    private static String get(Map<String, String> map, String key) {
        return map.get(Configuration.CONFIG.headerMap.get(key));
    }

}
