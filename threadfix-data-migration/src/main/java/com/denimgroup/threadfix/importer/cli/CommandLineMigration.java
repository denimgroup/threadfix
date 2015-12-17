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

import com.denimgroup.threadfix.StringEscapeUtils;
import com.denimgroup.threadfix.importer.config.SpringConfiguration;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Component
public class CommandLineMigration {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(CommandLineMigration.class);

    private static final String TABLE_PATTERN = "CREATE MEMORY TABLE (.*)";
    private static final String INSERT_PATTERN = "INSERT INTO (.*) VALUES";
    private static final String ACUNETIX_ESCAPE = "Cross-Site Scripting in HTML \\''script\\'' tag";
    private static final String ACUNETIX_ESCAPE_REPLACE = "Cross-Site Scripting in HTML &quot;script&quot; tag";

    private static Map<String, String> tableMap = map();

    private static final int SAME_SET_TRY_LIMIT = 10;


    public static void main(String[] args) {

        if (!check(args))
            return;

        try {
            String inputScript = args[0];
            String inputMySqlConfig = args[1];
            String outputScript = "import.sql";
            String outputMySqlConfigTemp = "jdbc_temp.properties";
            String errorLogFile = "error.log";
            String fixedSqlFile = "error_sql.sql";
            String errorLogAttemp1 = "error1.log";
            String infoLogFile = "info.log";
            String rollbackScript = "rollback.sql";

            deleteFile(outputScript);
            deleteFile(errorLogFile);
            deleteFile(errorLogFile);
            deleteFile(fixedSqlFile);
            deleteFile(errorLogAttemp1);
            deleteFile(infoLogFile);
            deleteFile(rollbackScript);

            PrintStream infoPrintStream = new PrintStream(new FileOutputStream(new File(infoLogFile)));
            System.setOut(infoPrintStream);

            long startTime = System.currentTimeMillis();

            copyFile(inputMySqlConfig, outputMySqlConfigTemp);

            LOGGER.info("Creating threadfix table in mySql database ...");
            ScriptRunner scriptRunner = SpringConfiguration.getContext().getBean(ScriptRunner.class);

            startTime = printTimeConsumed(startTime);
            convert(inputScript, outputScript);

            startTime = printTimeConsumed(startTime);

            PrintStream errPrintStream = new PrintStream(new FileOutputStream(new File(errorLogFile)));
            System.setErr(errPrintStream);


            LOGGER.info("Sending sql script to MySQL server ...");
            scriptRunner.run(outputScript, outputMySqlConfigTemp);

            long errorCount = scriptRunner.checkRunningAndFixStatements(errorLogFile, fixedSqlFile);
            long lastCount = errorCount + 1;
            int times = 1;
            int sameFixedSet = 0;

            // Repeat
            while (errorCount > 0) {
                //Flush error log screen to other file
                errPrintStream = new PrintStream(new FileOutputStream(new File(errorLogAttemp1)));
                System.setErr(errPrintStream);

                times += 1;

                if (errorCount == lastCount) {
                    sameFixedSet ++;
                } else {
                    sameFixedSet = 0;
                }

                LOGGER.info("Found " + errorCount + " error statements. Sending fixed sql script to MySQL server " + times + " times ...");
                scriptRunner.run(fixedSqlFile, outputMySqlConfigTemp);
                lastCount = errorCount;
                errorCount = scriptRunner.checkRunningAndFixStatements(errorLogAttemp1, fixedSqlFile);

                if (errorCount > lastCount || sameFixedSet > SAME_SET_TRY_LIMIT)
                    break;
            }

            if (errorCount > 0) {
                LOGGER.error("After " + times + " of trying, still found errors in sql script. " +
                        "Please check error_sql.sql and error1.log for more details.");
                LOGGER.info("Do you want to keep data in MySQL, and then import manually error statements (y/n)? ");
                try (java.util.Scanner in = new java.util.Scanner(System.in)) {
                    String answer = in.nextLine();
                    if (!answer.equalsIgnoreCase("y")) {
                        rollbackData(scriptRunner, outputMySqlConfigTemp, rollbackScript);
                    } else {
                        LOGGER.info("Data imported to MySQL, but still have some errors. Please check error_sql.sql and error1.log to import manually.");
                    }

                }

            } else {
                printTimeConsumed(startTime);
                LOGGER.info("Migration successfully finished");
            }

            deleteFile(outputMySqlConfigTemp);

        } catch (Exception e) {
            LOGGER.error("Error: ", e);
        }
    }

    private static void convert(String inputScript, String outputScript) {
        File file = new File(inputScript);

        LOGGER.info("Converting threadfix script to mySql script " + outputScript + " ...");

        File outputFile = new File(outputScript);

        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(outputFile);


            OutputStreamWriter osw = new OutputStreamWriter(fos);

            List<String> lines = FileUtils.readLines(file);

            osw.write("SET FOREIGN_KEY_CHECKS=0;\n");

            String table;
            for (String line : lines) {
                if (line != null && line.toUpperCase().startsWith("CREATE MEMORY TABLE ")) {
                    table = RegexUtils.getRegexResult(line, TABLE_PATTERN);
                    System.out.println("Create new table:" + table);
                    String[] tableName = table.split("\\(", 2);
                    if (tableName.length == 2) {
                        List<String> fieldList = list();
                        String[] fields = tableName[1].trim().replace("(", "").replace(")", "").split(",");
                        for (int i = 0; i< fields.length; i++) {
                            if (!"CONSTRAINT".equalsIgnoreCase(fields[i].trim().split(" ")[0])) {
                                String field = fields[i].trim().split(" ")[0].replace("\"", "");
                                if (!fieldList.contains(field))
                                    fieldList.add(field);
                            }
                        }
                        String fieldsStr = org.apache.commons.lang3.StringUtils.join(fieldList, ",");
                        tableMap.put(tableName[0].toUpperCase(), "(" + fieldsStr + ")");
                    }
                } else if (line != null && line.toUpperCase().startsWith("INSERT INTO ")) {
                    table = RegexUtils.getRegexResult(line, INSERT_PATTERN).toUpperCase();
                    if (tableMap.get(table) != null) {
                        line = line.replaceFirst(" " + table + " ", " " + table + tableMap.get(table) + " ");
                        if (line.contains(ACUNETIX_ESCAPE)) {
                            line = line.replace(ACUNETIX_ESCAPE, ACUNETIX_ESCAPE_REPLACE);
                        }
                        line = escapeString(line) + ";\n";

                        osw.write(line);
                    }
                }
            }
            osw.write("SET FOREIGN_KEY_CHECKS=1;\n");
            osw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static long printTimeConsumed(long startTime) {
        long endTime = System.currentTimeMillis();
        LOGGER.info("Finished in " + (endTime - startTime) + " ms");
        return endTime;
    }

    private static boolean check(String[] args) {
        if (args.length != 2) {
            LOGGER.warn("This program accepts two argument, threadfix script and mysql config files.");
            return false;
        }

        for (String arg: args) {
            File file = new File(arg);
            if (!file.exists()) {
                LOGGER.warn(arg + ": The file must exist.");
                return false;
            }

            if (file.isDirectory()) {
                LOGGER.warn(arg + ": The file must not be a directory.");
                return false;
            }
        }
        return true;
    }

    private static void copyFile(String oldFilePath, String newFilePath) throws IOException {
        FileUtils.writeStringToFile(new File(newFilePath), FileUtils.readFileToString(new File(oldFilePath)));
        LOGGER.info("Copied from " + oldFilePath + " to " + newFilePath);
    }

    private static void deleteFile(String oldFilePath) throws IOException {

        File fouput = new File(oldFilePath);
        if (fouput.exists() && fouput.isFile())
            if (fouput.delete())
                LOGGER.info("File " + oldFilePath + " has been deleted");
            else
                LOGGER.info("File " + oldFilePath + " has not been deleted");
    }

    private static String escapeString(String line) {

        if (line.toUpperCase().contains("INSERT INTO APPLICATION(")
                || line.toUpperCase().contains("INSERT INTO DEFAULTCONFIGURATION(")
                || line.toUpperCase().contains("INSERT INTO USER(")
                || line.toUpperCase().contains("INSERT INTO FINDING(")
                ){
            line = StringEscapeUtils.unescapeUnicode(line);
        }

        if (line.toUpperCase().contains("INSERT INTO FINDING")) {
            //Double backslash for multi backslash group
            line = line.replaceAll("(\\\\[\\\\]+)", "$1$1");
            // Double for single backslash
            line = line.replaceAll("([^\\\\])(\\\\[^nrt\\\\])", "$1\\\\$2");
        }

        return line;
    }

    private static void rollbackData(ScriptRunner runner, String jdbcConfig, String rollbackScript) {
        try {
            LOGGER.info("Rolling back data...");
            FileUtils.writeStringToFile(new File(rollbackScript), "DROP DATABASE threadfix;");
            runner.run(rollbackScript, jdbcConfig);
        } catch (IOException e) {
            LOGGER.error("Error", e);
        }
    }
}
