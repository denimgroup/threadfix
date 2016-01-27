////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
package com.denimgroup.threadfix.csv2ssl;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.checker.FormatChecker;
import com.denimgroup.threadfix.csv2ssl.checker.InteractiveConfiguration;
import com.denimgroup.threadfix.csv2ssl.parser.CSVToSSVLParser;
import com.denimgroup.threadfix.csv2ssl.util.InteractionUtils;
import com.denimgroup.threadfix.csv2ssl.util.Strings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import static com.denimgroup.threadfix.csv2ssl.checker.Configuration.CONFIG;

/**
 * Created by mac on 12/2/14.
 */
public class Main {

    public static void main(String[] args) {

        doConfigurationAndParsing(args);

        offerToSaveIfAppropriate();
    }

    private static void offerToSaveIfAppropriate() {
        if (!Configuration.CONFIG.loadedFromFile) {
            boolean keepAsking = InteractionUtils.getYNAnswer("Would you like to save configuration? (y/n)");
            while (keepAsking) {
                System.out.println("Where would you like to save this file? Enter 'exit' to quit.");

                String file = InteractionUtils.getLine();

                if ("exit".equals(file)) {
                    break;
                }

                File actualFile = new File(file);

                if (!actualFile.exists() || InteractionUtils.getYNAnswer("Overwrite current file? (y/n)")) {
                    Configuration.writeToFile(actualFile);
                    keepAsking = false;
                    System.out.println(
                            "To start this program again with this configuration, use the options " +
                                    Strings.CONFIG_FILE + actualFile.getAbsolutePath() + " " +
                                    Strings.TARGET_FILE + "{path to file you want to convert}"
                    );
                }
            }
        }
    }

    // public testing
    public static String doConfigurationAndParsing(String[] args) {
        configure(args);

        String xmlResult = CSVToSSVLParser.parse(CONFIG.csvFile.getAbsolutePath(), CONFIG.headers);

        if (FormatChecker.checkFormat(xmlResult)) {
            write(xmlResult);
        }

        return xmlResult;
    }

    private static void write(String xmlResult) {

        if (CONFIG.useStandardOut) {
            System.out.println(xmlResult);
        } else if (CONFIG.outputFile != null) {
            try {
                Files.write(Paths.get(CONFIG.outputFile.getAbsolutePath()), xmlResult.getBytes());
            } catch (IOException e) {
                System.out.println("Failed to write the SSVL contents to a file. Printing the stack trace.");
                e.printStackTrace();
            }
        }
    }

    private static void configure(String[] args) {
        Configuration.setFromArguments(args);

        WHILE: while (true) {
            switch (Configuration.getCurrentState()) {
                case VALID:
                    break WHILE;
                case NEEDS_HEADERS:
                    InteractiveConfiguration.configureHeaders();
                    break;
                case NEEDS_INPUT_FILE:
                    InteractiveConfiguration.configureInputFile();
                    break;
                case NEEDS_OUTPUT_FILE:
                    InteractiveConfiguration.configureOutputFile();
                    break;
            }
        }
    }
}
