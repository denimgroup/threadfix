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
package com.denimgroup.threadfix.csv2ssl;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.checker.FormatChecker;
import com.denimgroup.threadfix.csv2ssl.checker.InteractiveConfiguration;
import com.denimgroup.threadfix.csv2ssl.parser.CSVToSSVLParser;

import static com.denimgroup.threadfix.csv2ssl.checker.Configuration.CONFIG;

/**
 * Created by mac on 12/2/14.
 */
public class Main {

    public static void main(String[] args) {
        doParsing(args);
    }

    // public testing
    public static String doParsing(String[] args) {
        configure(args);

        String xmlResult = CSVToSSVLParser.parse(CONFIG.csvFile.getAbsolutePath(), CONFIG.headers);

        if (FormatChecker.checkFormat(xmlResult)) {
            System.out.println(xmlResult);
        }

        return xmlResult;
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
