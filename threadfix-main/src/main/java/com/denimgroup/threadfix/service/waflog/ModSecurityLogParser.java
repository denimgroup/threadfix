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

import java.util.Calendar;

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.WafRule;

public class ModSecurityLogParser extends WafLogParser {
	
	/**
	 * @param wafRuleDao
	 * @param securityEventDao
	 */
	public ModSecurityLogParser(WafRuleDao wafRuleDao, SecurityEventDao securityEventDao) {
		this.wafRuleDao = wafRuleDao;
		this.securityEventDao = securityEventDao;
	}

	@Override
	public SecurityEvent getSecurityEvent(String entry) {
		if (entry == null || entry.isEmpty()) 
			return null;
		
		String wafRuleNativeId = getRegexResult(entry, "\\[id \\\"([^\\\"]+)\\\"\\]");
		String type = getRegexResult(entry, "\\[msg \\\"([^\\\"]+)\\\"\\]");
		
		String time = getRegexResult(entry, "^\\[([^\\]]+)\\]");
		
		String attackerIP = getRegexResult(entry, "\\[client ([^\\]]+)\\]");
		
		String nativeId = getRegexResult(entry, "\\[unique_id \\\"([^\\\"]+)\\\"\\]");
		
		if (nativeId == null || securityEventDao.retrieveByNativeIdAndWafId(nativeId, wafId) != null)
			return null;
		
		WafRule rule = wafRuleDao.retrieveByWafAndNativeId(wafId, wafRuleNativeId);
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

}
