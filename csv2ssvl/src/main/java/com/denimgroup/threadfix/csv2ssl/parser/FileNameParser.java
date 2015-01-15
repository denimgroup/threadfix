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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.util.Strings;

/**
 * Created by mac on 12/3/14.
 */
public class FileNameParser {

    private FileNameParser(){}

    public static String parseFileName(String[] args) {
        for (String arg : args) {
            if (arg.startsWith(Strings.TARGET_FILE)) {
                return arg.substring(Strings.TARGET_FILE.length());
            }
        }

        throw new IllegalStateException(
                "The target file argument was not found. " +
                "This should have been caught by a format checker.");
    }

}
