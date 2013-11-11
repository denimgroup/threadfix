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
package com.denimgroup.threadfix.plugin.scanner;

import static org.junit.Assert.assertTrue;

import java.text.SimpleDateFormat;
import java.util.Locale;

import org.junit.Test;

import com.denimgroup.threadfix.plugin.scanner.service.channel.DateUtils;

public class DateUtilsParsingTests {

	@Test
	public void testGetCalendarFromString() {
		
		String[] tests = {
			"2011-05-24T13:05:41",
			"2011-03-16T21:47:46",
			"2011-03-16T21:45:56",
			"2011-03-16T21:47:56",
			"2011-03-17T06:45:44",
			"2011-03-16T21:43:15",
			"2011-03-16T21:44:38",
			"2011-03-16T21:45:16",
			"2011-04-04T14:55:48",
			"2011-03-16T21:50:46",
			"2011-03-16T21:51:00",
			"2012-01-18T14:21:57",
			"2012-01-23T12:24:30",
			"2011-11-17T11:13:05",
			"2011-11-17T11:11:42",
			"2012-03-08T09:54:46",
			"2012-03-08T11:52:48",
			"2012-03-08T12:00:05",
			"2012-08-02T12:56:42",
			"2012-08-02T16:46:17",
			"2013-05-24T01:48:27",
			"2013-09-06T16:38:28",
			"2013-05-08T03:58:25",
			"2013-07-10T01:06:01",
			"2013-10-01T20:54:03",
		};
		
		String formatString = "yyyy-MM-dd'T'HH:mm:ss";
		
		SimpleDateFormat format = new SimpleDateFormat(formatString, Locale.US);
		
		for (String string : tests) {
			String result = format.format(DateUtils.getCalendarFromString(formatString, string).getTime());
			assertTrue(string + " not = " + result, result.equals(string));
		}
	}
	
}
