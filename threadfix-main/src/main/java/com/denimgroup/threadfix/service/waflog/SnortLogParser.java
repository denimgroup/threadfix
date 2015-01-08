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
package com.denimgroup.threadfix.service.waflog;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.WafRule;

public class SnortLogParser extends WafLogParser {

	/**
	 * @param wafRuleDao
	 * @param securityEventDao
	 */
	public SnortLogParser(WafRuleDao wafRuleDao, SecurityEventDao securityEventDao) {
		this.wafRuleDao = wafRuleDao;
		this.securityEventDao = securityEventDao;
	}

	/**
	 * @param entryBuffer
	 * @return
	 */
	@Override
	public SecurityEvent getSecurityEvent(String entry) {
		if (entry == null || entry.isEmpty()) 
			return null;

		String[] csvSplit = entry.split(",");
		if (csvSplit == null || csvSplit.length < 5)
			return null;
		
		String sid  = csvSplit[2];
		String type = csvSplit[4];
		
		String time = csvSplit[0];
		
		String attackerIP = csvSplit[6];
		
		String[] toHash = {sid, type, time};
		String nativeId = hashArrayItems(toHash);
		
		if (nativeId == null || securityEventDao.retrieveByNativeIdAndWafId(nativeId, wafId) != null)
			return null;
		
		WafRule rule = wafRuleDao.retrieveByWafAndNativeId(wafId, sid);
		if (rule == null)
			return null;
		Calendar calendar = parseDate(time);
		
		SecurityEvent event = new SecurityEvent();
		
		event.setWafRule(rule);
		event.setImportTime(calendar);
		event.setLogText(entry);
		event.setAttackType(type);
		event.setNativeId(nativeId);
		event.setAttackerIP(attackerIP);
		
		return event;
	}
	
	public String hashArrayItems(String[] items) {
		if (items == null || items.length == 0)
			return null;
		
		StringBuffer buffer = new StringBuffer();
		for (String string : items)
			buffer.append(string);
		
		String toHash = buffer.toString();
		if (toHash.isEmpty())
			return null;

		try {
			MessageDigest message = MessageDigest.getInstance("MD5");
			message.update(toHash.getBytes(), 0, toHash.length());
			return new BigInteger(1, message.digest()).toString(16);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static Calendar parseDate(String time) {
		if (time == null)
			return null;
		String timeToParse = time;
		if (time.contains("."))
			timeToParse = time.substring(0, time.indexOf('.'));
		
		Date date = null;

		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd-HH:mm:ss");
		try {
			date = formatter.parse(timeToParse);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		
		if (date == null) return null;
		
		Calendar calendar = Calendar.getInstance();
		int temp = calendar.get(Calendar.YEAR);
		calendar.setTime(date);
		calendar.set(Calendar.YEAR, temp);
		
		return calendar;
	}

}
