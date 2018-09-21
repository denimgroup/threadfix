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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.util.Option;
import com.denimgroup.threadfix.csv2ssl.util.Strings;

/**
 * Created by mac on 12/3/14.
 */
public class ArgumentParser {

    private ArgumentParser(){}

    public static Option<String> parseTargetFileName(String[] args) {
        return getArgumentValue(Strings.OUTPUT_FILE, args);
    }

    public static Option<String> parseSourceFileName(String[] args) {
        return getArgumentValue(Strings.TARGET_FILE, args);
    }

    public static Option<String> parseConfigFileName(String[] args) {
        return getArgumentValue(Strings.CONFIG_FILE, args);
    }

    private static Option<String> getArgumentValue(String key, String[] args) {
        for (String arg : args) {
            if (arg.startsWith(key)) {
                String fileName = arg.substring(key.length());

                if (!fileName.equals("\"") && fileName.startsWith("\"") && fileName.endsWith("\"")) {
                    fileName = fileName.substring(1, fileName.length() - 1);
                }

                return Option.success(fileName);
            }
        }

        return Option.failure("No result found for " + "");
    }

}
