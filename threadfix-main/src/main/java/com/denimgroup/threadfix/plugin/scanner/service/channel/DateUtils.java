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
package com.denimgroup.threadfix.plugin.scanner.service.channel;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

import com.denimgroup.threadfix.service.SanitizedLogger;

public class DateUtils {
	
	protected static final SanitizedLogger log = new SanitizedLogger(DateUtils.class);
	
	private DateUtils() {}

	// return the parsed date object, or the null if parsing fails.
	public static Calendar getCalendarFromString(String formatString, String dateString) {
		
		log.info("Attempting to parse a calendar from " + dateString + " using " + formatString);
		
		Calendar result = null;
		
		if (formatString != null && !formatString.trim().equals("") &&
				dateString != null && !dateString.trim().equals("") ) {

			Date date = null;
			try {
				date = new SimpleDateFormat(formatString, Locale.US).parse(dateString);
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
		    log.info("Got " + new SimpleDateFormat(formatString, Locale.US).format(result.getTime()));
        } else {
            log.info("Got null instead of a date.");
        }
		
		return result;
	}
	
}
