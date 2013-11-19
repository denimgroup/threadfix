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
package com.denimgroup.threadfix.service.waflog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;

/**
 * @author mcollins
 * 
 */
public abstract class WafLogParser {
	
	protected WafRuleDao wafRuleDao;
	protected SecurityEventDao securityEventDao;
	protected BufferedReader bufferedReader;
	protected String wafId = null;
	
	/**
	 * Set the WAF ID to enable retrieval of WAF Rules to link Security Events to.
	 * @param wafId
	 */
	public void setWafId(String wafId) {
		if (wafId != null)
			this.wafId = wafId;
	}

	/**
	 * @param file
	 */
	public void setFile(MultipartFile file) {
		if (file != null) {
			try {
				bufferedReader = new BufferedReader(new InputStreamReader(file.getInputStream()));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * For RPC calls
	 * @param string
	 */
	public void setFileAsString(String string) {
		if (string != null)
			bufferedReader = new BufferedReader(new StringReader(string));
	}

	public List<SecurityEvent> parseInput() {
		if (bufferedReader == null)
			return null;

		List<SecurityEvent> events = new ArrayList<>();

		String line = null;

		try {
			while ((line = bufferedReader.readLine()) != null) {
				SecurityEvent event = getSecurityEvent(line);
				if (event != null)
					events.add(event);
			}
			bufferedReader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		for (SecurityEvent event : events)
			securityEventDao.saveOrUpdate(event);

		return events;
	}
	
	public static Calendar parseDate(String time) {
		Date date = null;
		//
		SimpleDateFormat formatter = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy");
		try {
			date = formatter.parse(time);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		if (date == null) return null;
		
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(date);
		
		return calendar;
	}
	
	protected static String getRegexResult(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null || regex.isEmpty())
			return null;

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find()) {
			return matcher.group(1);
		} else {
			return null;
		}
	}
	
	public abstract SecurityEvent getSecurityEvent(String line);
}
