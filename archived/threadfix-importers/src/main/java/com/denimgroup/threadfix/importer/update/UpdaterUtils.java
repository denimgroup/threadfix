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
package com.denimgroup.threadfix.importer.update;

import com.denimgroup.threadfix.importer.util.DateUtils;

import javax.annotation.Nonnull;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Calendar;

/**
 * Created by mac on 9/12/14.
 */
final class UpdaterUtils {

    private UpdaterUtils() {}

    @Nonnull
    public static Calendar getCalendarFromFirstLine(@Nonnull BufferedReader reader) {
        try {
            String possibleDateString = reader.readLine();

            Calendar calendarFromString =
                    DateUtils.getCalendarFromString(UpdaterConstants.DATE_PATTERN, possibleDateString);

            if (calendarFromString == null) {
                throw new IllegalArgumentException("Invalid reader passed to getCalendarFromFirstLine. " +
                        "The first line was " + possibleDateString +
                        " but was expecting a date in the format " + UpdaterConstants.DATE_PATTERN);
            }

            return calendarFromString;

        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "Received IOException while trying to read the first line from a BufferedReader: " + reader);
        }
    }

}
