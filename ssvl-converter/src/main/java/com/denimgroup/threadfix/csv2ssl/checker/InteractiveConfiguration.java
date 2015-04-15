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

import com.denimgroup.threadfix.csv2ssl.parser.FormatParser;
import com.denimgroup.threadfix.csv2ssl.util.Header;
import com.denimgroup.threadfix.csv2ssl.util.InteractionUtils;
import com.denimgroup.threadfix.csv2ssl.util.Option;

import java.io.File;
import java.util.Arrays;
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
        boolean readFromFile = getYNAnswer("Does the file contain the list of headers as the first line? (y/n)");

        if (readFromFile) {
            File file = getCsvFile();

            Option<String[]> option = FormatParser.parseFromFile(file);

            if (option.isValid()) {
                System.out.println("Got " + Arrays.toString(option.getValue()));
                boolean saveResult = getYNAnswer("Save this result? (y/n)");

                if (saveResult) {
                    CONFIG.headers = option.getValue();
                    CONFIG.shouldSkipFirstLine = true;
                    CONFIG.csvFile = file;
                    checkConfiguredHeaders();
                }
            } else {
                System.out.println("Unable to read line from file.");
            }

        } else {
            System.out.println("Please enter the headers.");
            String headers = getLine();
            System.out.println("Got " + headers);
            boolean saveResult = getYNAnswer("Save this result? (y/n)");

            if (saveResult) {
                CONFIG.headers = headers.split(",");
                CONFIG.shouldSkipFirstLine = false;
                checkConfiguredHeaders();
            }
        }
    }

    private static void checkConfiguredHeaders() {

        System.out.println("Checking configuration");

        Set<String> headerStringSet = new HashSet<String>(Arrays.asList(CONFIG.headers));

        for (Header header : Header.values()) {
            String configuredName = CONFIG.headerMap.get(header.text);

            if (headerStringSet.contains(configuredName)) {
                System.out.println("Success: configured header '" + configuredName + "' for field '" + header.text + "' was found in headers.");
            } else {
                System.out.println("Failure: configured header '" + configuredName + "' for field '" + header.text + "' was not found in headers.");
                if (header == Header.NATIVE_ID) {
                    System.out.println("You must configure a value for native ID.");
                }
            }
        }

        configureHeaderNames();
    }

    private static File getCsvFile() {
        if (CONFIG.csvFile == null) {
            return InteractionUtils.getValidFileFromStdIn("input");
        } else {
            return CONFIG.csvFile;
        }
    }

    public static void configureHeaderNames() {
        boolean reconfigure = getYNAnswer(
                "If you got Failures above for header names but the data is present in your file, you should configure the column mappings.\n" +
                "Configure mappings now? (y/n)");

        if (reconfigure) {
            Set<String> headerSet = new HashSet<String>();

            if (CONFIG.headers != null) {
                for (String header : CONFIG.headers) {
                    headerSet.add(header.trim());
                }
            }

            for (Header header : Header.values()) {
                getNewHeaderName(header, headerSet);
            }

            checkConfiguredHeaders();
        }
    }
    
    private static void getNewHeaderName(Header header, Set<String> inputHeaders) {

        while (true) {
            System.out.println(
                    "Please input the name of the header for " + header.description +
                            " or 'skip' to keep default value (" + header.text + ")"
            );
            String input = getLine();

            if (input.trim().equals("skip")) {
                return;
            } else if (inputHeaders.isEmpty() || inputHeaders.contains(input.trim())) {
                CONFIG.headerMap.put(header.text, input.trim());
                return;
            } else {
                System.out.println(input.trim() + " wasn't found in " + inputHeaders);
            }
        }
    }


    public static void configureInputFile() {
        CONFIG.csvFile = InteractionUtils.getValidFileFromStdIn("input (CSV or XLSX)");
    }

    public static void configureOutputFile() {
        System.out.println("Where would you like output to go? Please enter a file path or 'stdout' for console output.");
        String fileName = getLine();

        if (fileName.trim().equals("stdout")) {
            CONFIG.outputFile = null;
            CONFIG.useStandardOut = true;
        } else {
            File file = new File(fileName);

            if (file.isDirectory()) {
                System.out.println("You seem to have input the name of a directory. Please try again.");
                configureOutputFile();
            } else if (file.exists() && !file.canWrite()) {
                System.out.println("Java can't write to that file.");
                configureOutputFile();
            } else {
                CONFIG.outputFile = file;
                CONFIG.useStandardOut = false;
            }
        }
    }
}
