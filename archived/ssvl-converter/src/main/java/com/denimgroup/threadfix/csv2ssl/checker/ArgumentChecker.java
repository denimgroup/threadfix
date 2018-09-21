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

import com.denimgroup.threadfix.csv2ssl.util.Defaults;
import com.denimgroup.threadfix.csv2ssl.util.Strings;

import static com.denimgroup.threadfix.csv2ssl.util.Strings.*;

/**
 * Created by mac on 12/3/14.
 */
public class ArgumentChecker {

    public static boolean checkArguments(String[] args) {

        boolean hasTargetFile = false, hasFormatString = false;

        for (String arg : args) {

            boolean hasMatch = false;

            // Java 8's filter will be nice
            for (String argumentStart : ARGUMENTS) {
                if (arg.startsWith(argumentStart)) {
                    hasMatch = true;

                    if (!hasFormatString) {
                        hasFormatString = argumentStart.equals(FORMAT_FILE) || argumentStart.equals(FORMAT_STRING);
                    } else if (argumentStart.equals(FORMAT_FILE) || argumentStart.equals(FORMAT_STRING)) {
                        System.out.println("Only one of " + FORMAT_FILE + " and " + FORMAT_STRING + " is allowed.");
                        return false;
                    }

                    hasTargetFile = hasTargetFile || argumentStart.equals(TARGET_FILE);
                }
            }

            if (!hasMatch) {
                System.out.println("Unable to parse argument " + arg);
                return false;
            }
        }

        if (!hasTargetFile) {
            System.out.println("No target file specified. Use the " + TARGET_FILE + " option.");
            return false;
        }

        if (!hasFormatString) {
            hasFormatString = Strings.DEFAULT_HEADERS.isValid() || Defaults.ALLOW_FILE_HEADERS;
        }

        if (!hasFormatString) {
            System.out.println("No format string specified. Please use the " + FORMAT_FILE + " or " + FORMAT_STRING + " arguments.");
            return false;
        }

        return true;
    }


}
