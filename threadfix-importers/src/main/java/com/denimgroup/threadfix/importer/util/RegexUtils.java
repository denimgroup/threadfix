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

package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by mac on 2/4/14.
 */
public class RegexUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(RegexUtils.class);

    /**
     * Utility to prevent declaring a bunch of Matchers and Patterns.
     *
     * @param targetString
     * @param regex
     * @return result of applying Regex
     */
    public static String getRegexResult(String targetString, String regex) {
        if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty()) {
            LOG.warn("getRegexResult got null or empty input.");
            return null;
        }

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(targetString);

        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }

}
