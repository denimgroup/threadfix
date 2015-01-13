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

import com.denimgroup.threadfix.csv2ssl.checker.FormatChecker;
import com.denimgroup.threadfix.csv2ssl.util.Either;

import static com.denimgroup.threadfix.csv2ssl.checker.ArgumentChecker.checkArguments;
import static com.denimgroup.threadfix.csv2ssl.parser.CSVToSSVLParser.parse;
import static com.denimgroup.threadfix.csv2ssl.parser.FileNameParser.parseFileName;
import static com.denimgroup.threadfix.csv2ssl.parser.FormatParser.getHeaders;

/**
 * Created by mac on 12/2/14.
 */
public class Main {

    public static void main(String[] args) {
        if (checkArguments(args)) {

            Either<String[], String> headers = getHeaders(args, true);

            if (headers.isValid()) {
                String xmlResult = parse(parseFileName(args), headers.getValue());

                if (FormatChecker.checkFormat(xmlResult)) {
                    System.out.println(xmlResult);
                }

            } else {
                System.out.println(headers.getErrorMessage());
            }
        }
    }

}
