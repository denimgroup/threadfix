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
package com.denimgroup.threadfix.service;

import java.util.List;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.dao.SecurityEventDao;
import com.denimgroup.threadfix.data.dao.WafDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.service.waflog.WafLogParser;
import com.denimgroup.threadfix.service.waflog.WafLogParserFactory;

@Service
@Transactional(readOnly = false) // used to be true
public class LogParserServiceImpl implements LogParserService {
	
	private final SanitizedLogger log = new SanitizedLogger(LogParserService.class);

	private WafRuleDao wafRuleDao = null;
	private SecurityEventDao securityEventDao = null;
	private WafDao wafDao = null;
	private Integer wafId = null;
	private String fileAsString = null;
	private MultipartFile fileAsMultipartFile = null;

	/**
	 * @param wafRuleDao
	 * @param securityEventDao
	 */
	@Autowired
	public LogParserServiceImpl(WafRuleDao wafRuleDao, SecurityEventDao securityEventDao, WafDao wafDao) {
		this.wafRuleDao = wafRuleDao;
		this.securityEventDao = securityEventDao;
		this.wafDao = wafDao;
	}

	/**
	 * @param file
	 */
	@Override
	public void setFile(MultipartFile file) {
		if (file != null)
			this.fileAsMultipartFile = file;
	}
	
	@Override
	public void setWafId(Integer wafId) {
		if (wafId != null)
			this.wafId = wafId;
	}
	
	/**
	 * For RPC calls
	 */
	@Override
	public void setFileAsString(String string) {
		if (string != null)
			this.fileAsString = string;
	}

	/**
	 * @return
	 */
	@Override
	@Transactional(readOnly = false)
	public List<SecurityEvent> parseInput() {
		if (wafId == null || (fileAsString == null && fileAsMultipartFile == null)) {
			return null;
		}
		
		Waf waf = null;
		
		try {
			Integer intWafId = Integer.valueOf(wafId);
			waf = wafDao.retrieveById(intWafId);
		} catch (NumberFormatException e) {
			log.error("The WAF id given was non-numeric and no WAF could be retrieved. Returning null.");
		}
		
		if (waf == null || waf.getWafType() == null) {
			return null;
		}
		
		WafLogParserFactory factory = new WafLogParserFactory(wafRuleDao, securityEventDao);
		WafLogParser parser = factory.getTracker(waf.getWafType().getName());
		if (parser == null) {
			return null;
		}
		
		parser.setWafId(String.valueOf(wafId));
		
		if (fileAsString != null) {
			parser.setFileAsString(fileAsString);
		} else {
			parser.setFile(fileAsMultipartFile);
		}
		
		log.info("About to parse " + waf.getWafType().getName() + " log file.");
		
		List<SecurityEvent> events = parser.parseInput();
		
		if (events.size() != 0) {
			log.info("Found " + events.size() + " security events in the " + waf.getWafType().getName() + " log.");
		} else {
			log.warn("Found no security events in the " + waf.getWafType().getName() + " log.");
		}
		
		return events;
	}

}
