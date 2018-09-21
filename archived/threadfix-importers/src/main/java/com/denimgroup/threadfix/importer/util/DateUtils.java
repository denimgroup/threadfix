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
import javax.annotation.Nullable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

public class DateUtils {

    protected static final SanitizedLogger  log       = new SanitizedLogger(DateUtils.class);
    private   static final SimpleDateFormat utcFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);

    private DateUtils() {
    }

    /**
     * This method parses strings using the date format "yyyy-MM-dd'T'HH:mm:ss'Z'" which is ISO 8601
     * @param dateString
     * @return
     */
    @Nullable
    public static Calendar getCalendarFromUTCString(@Nullable String dateString) {

        if (dateString != null && !dateString.trim().equals("")) {
            try {
                return getCalendarFromString(utcFormat, dateString);


            } catch (IllegalArgumentException e) {
                log.error("An invalid date string was passed to the SimpleDateFormat constructor: " + dateString);
            }
        }

        return null;
    }

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

    public static Calendar getCalendarFromStringAndMultipleFormats(String dateString, @Nonnull String... dateFormats) {

        for (String dateFormat : dateFormats) {
            Calendar validate = getCalendarFromString(dateFormat, dateString);
            if (validate != null) {
                return validate;
            }
        }

        return null;
    }

    /**
     * This method allows caching of the SimpleDateFormat to avoid unnecessary object creation
     * @return resulting Calendar, or null if parsing fails for any reason
     */
    public static Calendar getCalendarFromString(@Nonnull SimpleDateFormat format, String dateString) {
        log.debug("Attempting to parse a calendar from " + dateString + " using " + format.toPattern());

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
            log.debug("Got " + format.format(result.getTime()));
        } else {
            log.debug("Got null instead of a date.");
        }

        return result;
    }

    /**
     *
     * HTTP traffic all follows a pattern, so if you can see an HTTP response then you
     * can parse out the date the request was made. This method does that.
     * @param httpTrafficString
     * @return
     */
    public static Calendar attemptToParseDateFromHTTPResponse(String httpTrafficString) {
        if (httpTrafficString == null) {
            return null;
        }

        String dateString = RegexUtils.getRegexResult(httpTrafficString, "Date: ([^\n]+)");

        if (dateString != null && !dateString.isEmpty()) {
            return DateUtils.getCalendarFromString("EEE, dd MMM yyyy kk:mm:ss zzz", dateString);
        } else {
            return null;
        }
    }

    public static Calendar getLatestCalendar(Calendar... calendars) {
        Calendar latest = null;

        for (Calendar calendar : calendars) {
            if (calendar != null) {
                if (latest == null || calendar.after(latest)) {
                    latest = calendar;
                }
            }
        }

        return latest;
    }
	
}
