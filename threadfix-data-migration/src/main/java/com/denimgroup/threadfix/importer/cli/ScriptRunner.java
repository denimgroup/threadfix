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

    public boolean checkRunning(String errorLogFile, String fixedSqlFile) {

        boolean result = true;
        File outputFile = new File(fixedSqlFile);

        FileOutputStream fos = null;
        try {
            List<String> lines = FileUtils.readLines(new File(errorLogFile));

            if (lines != null && lines.size() > 1) {
                fos = new FileOutputStream(outputFile);
                OutputStreamWriter osw = new OutputStreamWriter(fos);

                String preLine = null;
                osw.write("SET FOREIGN_KEY_CHECKS=0;\n");
                for (String currentLine: lines) {

                   if (currentLine.toLowerCase().contains("incorrect string value") && !currentLine.contains("Error executing: INSERT INTO")) {
                       if (preLine != null) {
                           String fixedStatement = preLine.replace("Error executing: ", "").replaceAll("[^\\x00-\\x7F]", "");
                           osw.write(fixedStatement + ";\n");
                       }
                   }
                  preLine = currentLine;
                }

                osw.write("SET FOREIGN_KEY_CHECKS=1;\n");
                osw.close();
                result = false;
            }
        } catch (IOException e) {
            LOGGER.error("Error", e);
        }
        return result;
    }

    public void readErrorLog(String errorLogAttemp1) {
        try {
            String error = FileUtils.readFileToString(new File(errorLogAttemp1));
            String detailMsg = "";
            if (error != null && error.split("VALUES\\(").length > 1)
                detailMsg = " " + error.split("\\(ID")[0] + " with ID " + error.split("VALUES\\(")[1].split(",")[0] + ".";

            LOGGER.error("Unable to migrate data." + detailMsg + " Check " + errorLogAttemp1 + " for more details.");
        } catch (Exception e) {
            LOGGER.error("Error", e);
        }
    }

}
