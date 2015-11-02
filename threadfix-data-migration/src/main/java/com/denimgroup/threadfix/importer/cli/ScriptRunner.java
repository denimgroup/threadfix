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

package com.denimgroup.threadfix.importer.cli;

import com.denimgroup.threadfix.importer.util.RegexUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

@Component
public class ScriptRunner {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(ScriptRunner.class);

    public boolean run(@Nonnull String scriptFile, @Nonnull String sqlConfigFile) {

        InputStream input = null;
        boolean isSuccess = true;
        // Create MySql Connection
        try {
            Properties prop = new Properties();
            input = new FileInputStream(sqlConfigFile);

            // load a properties file
            prop.load(input);

            Class.forName(prop.getProperty("jdbc.driverClassName"));

            Connection con = DriverManager.getConnection(
                    prop.getProperty("jdbc.url"), prop.getProperty("jdbc.username"), prop.getProperty("jdbc.password"));

            // Initialize object for ScripRunner
            com.ibatis.common.jdbc.ScriptRunner sr = new com.ibatis.common.jdbc.ScriptRunner(con, false, false);

            // Give the input file to Reader
            Reader reader = new BufferedReader(
                    new FileReader(scriptFile));

            // Execute script
            sr.runScript(reader);

        } catch (Exception e) {
            LOGGER.error("Failed to Execute" + scriptFile
                    + " The error is " + e.getMessage());
            isSuccess = false;

        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return isSuccess;
    }

    public long checkRunningAndFixStatements(String errorLogFile, String fixedSqlFile) {

        long errorCount = 0;

        File outputFixedScript = new File(fixedSqlFile);

        FileOutputStream fos = null;
        try {
            List<String> lines = FileUtils.readLines(new File(errorLogFile));

            if (lines != null && lines.size() > 1) {
                fos = new FileOutputStream(outputFixedScript);
                OutputStreamWriter osw = new OutputStreamWriter(fos);

                String preLine = null;
                Map<String, Object> map = new HashMap<>();
                osw.write("SET FOREIGN_KEY_CHECKS=0;\n");
                for (String currentLine: lines) {

                    if (!currentLine.contains("Error executing: INSERT INTO")) {
                        // Remove all weird characters if they cause 'incorrect string value' SQLExeption
                        if (currentLine.toLowerCase().contains("incorrect string value")) {
                            if (preLine != null) {
                                String fixedStatement = preLine.replace("Error executing: ", "").replaceAll("[^\\x00-\\x7F]", "");
                                osw.write(fixedStatement + ";\n");
                            }
                        }
                        // If there is unknown column, then delete that column and its value
                        else if (currentLine.contains("MySQLSyntaxErrorException: Unknown column")) {
                            osw.write(getFixedUnknownColStatement(currentLine, preLine.replace("Error executing: ", "")));
                        }
                        // too long string for column, cut it off
                        else if (currentLine.contains("Data too long for column")) {
                            map = exactTableFromString(preLine);
                            if (map == null || map.isEmpty()) {
                                LOGGER.error("Unable to fix statement: " + preLine);
                                LOGGER.error("Error was: " + currentLine);
                                osw.write(preLine.replace("Error executing: ", "") + ";\n");
                                continue;
                            }
                            osw.write(fixLongColumnStatement(preLine, currentLine, map));
                        }
                        // Older version of MySQL doesn't take time with fraction like '2015-10-28 13:01:59.289000000'
                        else if (currentLine.contains("Data truncation: Incorrect datetime value")) {
                            osw.write(fixDateWrongStatement(preLine, currentLine));
                        }
                        // Unresolved-yet SQLException, then write whole statement to fixed Sql script
                        else {
                            if (preLine != null && preLine.contains("Error executing: INSERT INTO")) {
                                osw.write(preLine.replace("Error executing: ", "") + ";\n");
                            }
                        }
                    } else {
                        errorCount += 1;
                    }
                    preLine = currentLine;
                }

                osw.write("SET FOREIGN_KEY_CHECKS=1;\n");
                osw.close();
            }
        } catch (IOException e) {
            LOGGER.error("Error", e);
        }
        return errorCount;
    }

    private static String fixDateWrongStatement(String preLine, String currentLine) {
        String errorValue = getColName(currentLine, "Incorrect datetime value: (.*) for column");
        String newValue = errorValue;
        boolean isString = false;
        if (errorValue.startsWith("'") && errorValue.endsWith("'")) {
            isString = true;
            newValue = newValue.substring(1);
            newValue = newValue.substring(0, errorValue.length() - 1);
        }
        String[] timeParts = newValue.split(".");
        if (timeParts.length == 2) {
            newValue = timeParts[0];
        }
        if (isString) {
            newValue = "'" + newValue + "'";
        }
        String fixedStatement = preLine.replace("Error executing: ", "").replaceAll(errorValue, newValue);
        return fixedStatement + ";\n";
    }

    private static String fixLongColumnStatement(String preLine, String currentLine, Map map) {
        String colName = getColName(currentLine, "Data too long for column '(.*)' at");
        String colDef = getColDef(colName, (String)map.get("tableName"));
        if (colDef != null) {
            String noOfChar = RegexUtils.getRegexResult(colDef, colName.toUpperCase() + " VARCHAR\\((.*)\\)");
            if (noOfChar != null && !noOfChar.isEmpty()) {
                try {
                    int noOfCharInt = Integer.parseInt(noOfChar);
                    Map<String, String> fieldMap = (Map) map.get("tableFields");
                    String oldValue = fieldMap.get(colName.toUpperCase());
                    boolean isString = false;
                    if (oldValue.startsWith("'") && oldValue.endsWith("'")) {
                        isString = true;
                        oldValue = oldValue.substring(1);
                        oldValue = oldValue.substring(0, oldValue.length() - 1);
                    }
                    oldValue = oldValue.substring(0, noOfCharInt);
                    if (isString)
                        oldValue = "'" + oldValue + "'";

                    String colList = "";
                    String colValues = "";
                    for (String key : fieldMap.keySet()) {
                        if (!key.equalsIgnoreCase(colName)) {
                            colList = colList + key + ",";
                            colValues = colValues + fieldMap.get(key) + ",";
                        }
                    }
                    colList = colList + colName.toUpperCase();
                    colValues = colValues + oldValue;
                    String fixedStatement = "INSERT INTO " + map.get("tableName") + "(" + colList + ") VALUES" + "(" + colValues + ")" + ";\n";
                    return fixedStatement;

                } catch (NumberFormatException exp) {
                    exp.printStackTrace();
                }
            } else {
                LOGGER.error("Couldn't find column definition");
            }
        }
        LOGGER.error("Unable to fix " + preLine);
        String fixedStatement = preLine.replace("Error executing: ", "");
        return fixedStatement + ";\n";
    }

    private static String getColDef(String colName, String tableName) {
        try {
            String startStatement = ("Create new table:" + tableName + "(").toUpperCase();
            colName = colName.toUpperCase();
            String FIELD_PATTERN = "," + colName + " " + "(.*)";

            List<String> logLines = FileUtils.readLines(new File("info.log"));
            for (String logLine : logLines) {
                logLine = logLine.toUpperCase();
                if (logLine.startsWith(startStatement)) {

                    String def = RegexUtils.getRegexResult(logLine, FIELD_PATTERN);
                    def = def.split(",")[0];
                    return colName + " " + def;
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static Map<String, Object> exactTableFromString(String currentLine) {
        String COL_LIST_PATTERN = "\\((.*)\\) VALUES\\(";
        String VALUE_LIST_PATTERN = "\\) VALUES\\((.*)\\)";
        String TABLE_PATTERN = "INSERT INTO (.*)\\(ID";
        String colListStr = RegexUtils.getRegexResult(currentLine, COL_LIST_PATTERN);
        String valueListStr = RegexUtils.getRegexResult(currentLine, VALUE_LIST_PATTERN).trim();
        String table = RegexUtils.getRegexResult(currentLine, TABLE_PATTERN);
        String[] colList = colListStr.split(",");
        String[] valList = valueListStr.split(",");
        if (colList.length != valList.length || colList.length == 0) {
            LOGGER.error("Error in: " + currentLine);
            LOGGER.error("Number of values and columns don't match.");
            return null;
        }

        Map<String, Object> map = new HashMap<>();
        map.put("tableName", table);

        Map<String, String> fieldMap = new HashMap<>();
        for (int i=0; i < colList.length; i++) {
            fieldMap.put(colList[i].toUpperCase(), valList[i]);
        }
        map.put("tableFields", fieldMap);

        return map;
    }

    private String getFixedUnknownColStatement(String errorStr, String originalStatement) {
        String ERROR_COL_PATTERN = "Unknown column '(.*)' in 'field list'";
        String COL_LIST_PATTERN = "\\((.*)\\) VALUES\\(";
        String VALUE_LIST_PATTERN = "\\) VALUES\\((.*)";
        String TABLE_PATTERN = "INSERT INTO (.*)\\(ID";
        String colName = RegexUtils.getRegexResult(errorStr, ERROR_COL_PATTERN);
        String colListStr = RegexUtils.getRegexResult(originalStatement, COL_LIST_PATTERN);
        String valueListStr = RegexUtils.getRegexResult(originalStatement, VALUE_LIST_PATTERN).trim();
        if (valueListStr.endsWith(")"))
            valueListStr = valueListStr.substring(0, valueListStr.length()-1);
        String table = RegexUtils.getRegexResult(originalStatement, TABLE_PATTERN);

        int colIndex = findColIndex(colListStr, colName);
        String updatedColList = removeCol(colListStr, colIndex);
        String updatedValList = removeValue(valueListStr, colIndex, colListStr.split(",").length);

        String returnStr = "INSERT INTO " + table + "(" + updatedColList + ") VALUES" + "(" + updatedValList + ")";

        return returnStr + ";\n";
    }

    private static String getColName(String errorStr, String colPattern) {
        return RegexUtils.getRegexResult(errorStr, colPattern);
    }

    private String removeCol(String valueListStr, Integer colIndex) {
        if (colIndex == null)
            return valueListStr;

        String[] valList = valueListStr.split(",");
        if (colIndex >= valList.length || valList.length < 2)
            return valueListStr;

        StringBuffer newStr = new StringBuffer();
        for (int i =0 ;i<valList.length;i++)
            if ( i != colIndex)
                newStr.append("," + valList[i]);

        return newStr.toString().replaceFirst(",", "");
    }

    private String removeValue(String valueListStr, Integer colIndex, Integer totalCol) {
        if (colIndex == null)
            return valueListStr;

        String separator = ",";
        int index = 1;
        String inSearchStr = valueListStr.substring(valueListStr.indexOf(separator));
        String needRemoveVal = valueListStr.substring(0, valueListStr.indexOf(separator));
        StringBuffer buildingStr = new StringBuffer();

        while (index <= colIndex) {

            buildingStr.append(needRemoveVal);

            if (index < totalCol - 1) {
                if (inSearchStr.startsWith(",'")) {
                    needRemoveVal = inSearchStr.substring(0, inSearchStr.indexOf("',") + 1);
                    inSearchStr = inSearchStr.substring(inSearchStr.indexOf("',") + 1);
                } else if (inSearchStr.startsWith(",")) {

                    inSearchStr = inSearchStr.replaceFirst(",", "");
                    needRemoveVal = "," + inSearchStr.substring(0, inSearchStr.indexOf(","));
                    inSearchStr = inSearchStr.substring(inSearchStr.indexOf(","));
                }
            } else {
                if (inSearchStr.startsWith(",'") || inSearchStr.startsWith(",")) {
                    needRemoveVal = inSearchStr;
                    inSearchStr = "";
                } else needRemoveVal = null;

            }

            index ++;
        }

        if (index == colIndex + 1 && needRemoveVal != null) {
            buildingStr.append(inSearchStr);
            return buildingStr.toString();
        } else {
            return valueListStr;
        }

    }

    private Integer findColIndex(String colListStr, String colName) {
        String[] colList = colListStr.split(",");
        for (int i =0 ;i<colList.length;i++)
            if (colList[i].trim().equalsIgnoreCase(colName))
                return i;
        return null;
    }

}
