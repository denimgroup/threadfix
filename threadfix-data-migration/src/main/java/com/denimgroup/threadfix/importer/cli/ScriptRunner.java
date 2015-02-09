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
import java.util.List;
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
