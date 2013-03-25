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
package com.denimgroup.threadfix.service;

import java.util.Calendar;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.dao.WafDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.dao.WafTypeDao;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGenerator;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGeneratorFactory;

@Service
@Transactional(readOnly = true)
public class WafServiceImpl implements WafService {
	
	private final SanitizedLogger log = new SanitizedLogger("WafService");

	private WafDao wafDao = null;
	private WafTypeDao wafTypeDao = null;
	private WafRuleDao wafRuleDao = null;
	private WafRuleDirectiveDao wafRuleDirectiveDao = null;
	private VulnerabilityDao vulnerabilityDao = null;

	@Autowired
	public WafServiceImpl(WafDao wafDao, WafTypeDao wafTypeDao, WafRuleDao wafRuleDao,
			VulnerabilityDao vulnerabilityDao, WafRuleDirectiveDao wafRuleDirectiveDao) {
		this.wafDao = wafDao;
		this.wafTypeDao = wafTypeDao;
		this.wafRuleDao = wafRuleDao;
		this.vulnerabilityDao = vulnerabilityDao;
		this.wafRuleDirectiveDao = wafRuleDirectiveDao;
	}

	@Override
	public List<Waf> loadAll() {
		return wafDao.retrieveAll();
	}

	@Override
	public Waf loadWaf(int wafId) {
		return wafDao.retrieveById(wafId);
	}

	@Override
	public Waf loadWaf(String name) {
		return wafDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeWaf(Waf waf) {
		if (waf.getCurrentId() == null && waf.getWafType() != null)
			waf.setCurrentId(waf.getWafType().getInitialId());
		wafDao.saveOrUpdate(waf);
	}

	@Override
	@Transactional(readOnly = false)
	public void deleteById(int wafId) {
		Waf waf = loadWaf(wafId);
		
		if (waf != null) {
			log.info("Deleting WAF with ID " + wafId);
			
			if (waf.getWafRules() != null) {
				for (WafRule rule : waf.getWafRules()) {
					wafRuleDao.delete(rule);
				}
			}
			
			waf.setActive(false);
			wafDao.saveOrUpdate(waf);
		}
	}

	@Override
	public List<WafType> loadAllWafTypes() {
		return wafTypeDao.retrieveAll();
	}

	@Override
	public WafType loadWafType(int wafId) {
		return wafTypeDao.retrieveById(wafId);
	}

	@Override
	public WafType loadWafType(String name) {
		return wafTypeDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void generateWafRules(Waf waf, WafRuleDirective directive) {
		if (waf == null || waf.getApplications() == null || waf.getApplications().size() == 0
				|| waf.getWafType() == null) {
			return;
		}
		
		WafRuleDirective editedDirective = directive;
		
		if (editedDirective == null && waf.getLastWafRuleDirective() != null) {
			editedDirective = waf.getLastWafRuleDirective();
		}

		RealTimeProtectionGeneratorFactory factory = new RealTimeProtectionGeneratorFactory(
															wafRuleDao, wafRuleDirectiveDao);
		RealTimeProtectionGenerator generator = factory.getTracker(waf.getWafType().getName());
		if (generator != null) {
			if (editedDirective == null) {
				editedDirective = generator.getDefaultDirective(waf);
			}
			
			List<WafRule> wafRuleList = generator.generateRules(waf, editedDirective);
			waf.setWafRules(wafRuleList);
			waf.setLastWafRuleDirective(editedDirective);
			saveOrUpdateRules(waf, editedDirective);
			storeWaf(waf);
		}
	}

	@Override
	@Transactional(readOnly = false)
	public void generateWafRules(Waf waf, String directiveName) {
		if (waf == null || waf.getId() == null || waf.getWafType() == null 
				|| waf.getWafType().getId() == null)
			return;
		WafRuleDirective directive = null;
		if (directiveName != null && !directiveName.isEmpty()) {
			WafRuleDirective tempDirective = wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(
														waf.getWafType(), directiveName);
			if (tempDirective != null)
				directive = tempDirective;
		}
		generateWafRules(waf, directive);
	}

	/**
	 * @param waf
	 */
	@Override
	@Transactional(readOnly = false)
	public void saveOrUpdateRules(Waf waf, WafRuleDirective directive) {
		Calendar now = Calendar.getInstance();
		for (WafRule wafRule : waf.getWafRules()) {
			if (wafRule.isNew()) {
				wafRule.setWafRuleDirective(directive);
				wafRule.setWaf(waf);
				wafRuleDao.saveOrUpdate(wafRule);

				Vulnerability vuln = wafRule.getVulnerability();
				vuln.setWafRuleGeneratedTime(now);
				vulnerabilityDao.saveOrUpdate(vuln);
			}
		}
	}
	
	@Override
	public String getAllRuleText(Waf waf) {
		if (waf == null || waf.getWafRules() == null ||
				waf.getWafRules().size() == 0){
			return null;
		}
		
		List<WafRule> rules = loadCurrentRules(waf);
		
		StringBuffer buffer = new StringBuffer();
		
		String prefix = null, suffix = null;
		String name = waf.getWafType().getName();
		if (RealTimeProtectionGenerator.hasStartAndEnd(name)) {
			prefix = RealTimeProtectionGenerator.getStart(name, rules);
			suffix = RealTimeProtectionGenerator.getEnd(name, rules);
		}
		
		if (prefix != null) {
			buffer.append(prefix);
		}
		
		if (rules != null) {
			for (WafRule rule : rules) {
				if (rule != null && rule.getIsNormalRule()) {
					buffer.append(rule.getRule()).append('\n');
				}
			}
		}
		
		if (suffix != null) {
			buffer.append(suffix);
		}

		return buffer.toString();
	}
	
	@Override
	public List<WafRule> loadCurrentRules(Waf waf) {
		if (waf == null)
			return null;
		else if (waf.getLastWafRuleDirective() == null || waf.getLastWafRuleDirective().getId() == null)
			return waf.getWafRules();
		else
			return wafRuleDao.retrieveByWafAndDirective(waf, waf.getLastWafRuleDirective());
	}

}