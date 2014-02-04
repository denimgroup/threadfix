////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
import org.jetbrains.annotations.Nullable;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

public class DateUtils {
	
	protected static final SanitizedLogger log = new SanitizedLogger(DateUtils.class);
	
	private DateUtils() {}

	// return the parsed date object, or the null if parsing fails.
    @Nullable
	public static Calendar getCalendarFromString(@Nullable String formatString, @Nullable String dateString) {

        if (formatString != null && !formatString.trim().equals("")) {
            try {
                return getCalendarFromString(new SimpleDateFormat(formatString, Locale.US), dateString);
            } catch (IllegalArgumentException e) {
                log.error("An invalid format string was passed to the SimpleDateFormat constructor: " + formatString);
            }
        }

        return null;
	}

    /**
     * This method allows caching of the SimpleDateFormat to avoid unnecessary object creation
     * @return resulting Calendar, or null if parsing fails for any reason
     */
    public static Calendar getCalendarFromString(SimpleDateFormat format, String dateString) {
        log.info("Attempting to parse a calendar from " + dateString + " using " + format.toPattern());

        Calendar result = null;

        if (format != null && dateString != null && !dateString.trim().equals("") ) {

            Date date = null;
            try {
                date = format.parse(dateString);
            } catch (ParseException e) {
                log.warn("Parsing of date from '" + dateString + "' failed.", e);
            }

            if (date != null) {
                log.debug("Successfully parsed date: " + date + ".");
                Calendar scanTime = new GregorianCalendar();
                scanTime.setTime(date);
                result = scanTime;
            } else {
                log.warn("There was an error parsing the date, check the format and regex.");
            }
        }

        if (result != null) {
            log.info("Got " + format.format(result.getTime()));
        } else {
            log.info("Got null instead of a date.");
        }

        return result;
    }
	
}
