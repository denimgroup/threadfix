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

package com.denimgroup.threadfix.importer.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;

/**
 * Created by mac on 12/18/13.
 */
public class IntegerUtils {

    private static final SanitizedLogger log = new SanitizedLogger(IntegerUtils.class);

    private IntegerUtils(){}

    /**
     * Returns Integer.valueOf(input) with exception handling. Will return -1 if it fails to parse.
     *
     * @param input String representation of an integer
     * @return the parsed number, or -1 on failure
     */
    public static int getPrimitive(String input) {

        if (input == null) {
            log.warn("Null string passed to getPrimitive");
            return -1;
        }

        if (!input.matches("^[0-9]+$")) {
            log.warn("Non-numeric String encountered.");
            return -1;
        }

        try {
            return Integer.valueOf(input);
        } catch (NumberFormatException e) {
            log.warn("Non-numeric input encountered: " + input, e);
            return -1;
        }
    }

    /**
     * Returns Integer.valueOf(input) with exception handling. Will return null if it fails to parse.
     *
     * @param input String representation of an integer
     * @return the parsed number, or null on failure
     */
    public static Integer getIntegerOrNull(@Nonnull String input) {

        if (!input.matches("^[0-9]+$")) {
            log.warn("Non-numeric String encountered: " + input);
            return null;
        }

        try {
            return Integer.valueOf(input);
        } catch (NumberFormatException e) {
            log.warn("Non-numeric input encountered: " + input, e);
            return null;
        }
    }
}
