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
package com.denimgroup.threadfix.csv2ssl.checker;

import com.denimgroup.threadfix.csv2ssl.util.InteractionUtils;
import com.denimgroup.threadfix.csv2ssl.util.Strings;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import static com.denimgroup.threadfix.csv2ssl.checker.Configuration.CONFIG;
import static com.denimgroup.threadfix.csv2ssl.util.InteractionUtils.getLine;
import static com.denimgroup.threadfix.csv2ssl.util.InteractionUtils.getYNAnswer;

/**
 * Created by mcollins on 1/21/15.
 */
public class InteractiveConfiguration {

    public static void configureHeaders() {
        boolean readFromFile = getYNAnswer("Does the CSV file contain the list of headers as the first line? (y/n)");

        if (readFromFile) {
            File file = getCsvFile();

            String firstLine = InteractionUtils.getFirstLine(file);

            if (firstLine == null) {
                System.out.println("Unable to read line from file.");
            } else {
                System.out.println("Got " + firstLine);
                boolean saveResult = getYNAnswer("Save this result?");

                if (saveResult) {
                    CONFIG.headers = firstLine.split(",");
                    CONFIG.shouldSkipFirstLine = true;
                }
            }
        } else {
            System.out.println("Please enter the headers.");
            String headers = getLine();
            System.out.println("Got " + headers);
            boolean saveResult = getYNAnswer("Save this result?");

            if (saveResult) {
                CONFIG.headers = headers.split(",");
                CONFIG.shouldSkipFirstLine = false;
            }
        }
    }

    private static File getCsvFile() {
        if (CONFIG.csvFile == null) {
            return InteractionUtils.getValidFileFromStdIn("CSV");
        } else {
            return CONFIG.csvFile;
        }
    }

    public static void configureHeaderNames() {
        boolean reconfigure = getYNAnswer(
                "Would you like to update the header titles?\n" +
                "For example, 'CWE' corresponds to 'Vulnerability Type' in the CSV, not 'CWE'. (y/n)");

        if (reconfigure) {
            Set<String> headerSet = new HashSet<String>();

            if (CONFIG.headers != null) {
                for (String header : CONFIG.headers) {
                    headerSet.add(header.trim());
                }
            }

            getNewHeaderName("CWE (number, ex. 79)", Strings.CWE, headerSet);
            getNewHeaderName("Long Description", Strings.LONG_DESCRIPTION, headerSet);
            getNewHeaderName("Native ID (identifying String, ex. 72457)", Strings.NATIVE_ID, headerSet);
            getNewHeaderName("Parameter (String, ex. username)", Strings.PARAMETER, headerSet);
            getNewHeaderName("Path (String, ex. /login.jsp)", Strings.URL, headerSet);
            getNewHeaderName("Severity (String, one of 'Information', 'Low', 'Medium', 'High', 'Critical' or a number from 1 to 5)", Strings.SEVERITY, headerSet);
            getNewHeaderName("FindingDate (Must be in the format " + Strings.DATE_FORMAT + ")", Strings.FINDING_DATE, headerSet);
            getNewHeaderName("Issue ID (Jira, TFS, etc. ID format)", Strings.ISSUE_ID, headerSet);
        }
    }
    
    private static void getNewHeaderName(String prompt, String key, Set<String> inputHeaders) {

        while (true) {
            System.out.println(
                    "Please input the name of the header for " + prompt +
                            " or 'skip' to keep default value (" + key + ")"
            );
            String input = getLine();

            if (input.trim().equals("skipme")) {
                return;
            } else if (inputHeaders.isEmpty() || inputHeaders.contains(input.trim())) {
                CONFIG.headerMap.put(key, input.trim());
            } else {
                System.out.println(input.trim() + " wasn't found in " + inputHeaders);
            }
        }
    }


    public static void configureInputFile() {
        CONFIG.csvFile = InteractionUtils.getValidFileFromStdIn("CSV");
    }

    public static void configureOutputFile() {
        CONFIG.outputFile = InteractionUtils.getValidFileFromStdIn("output");
    }
}
