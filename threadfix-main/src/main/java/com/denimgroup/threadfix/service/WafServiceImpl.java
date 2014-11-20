////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGenerator;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGeneratorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Calendar;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional(readOnly = false) // used to be true
public class WafServiceImpl implements WafService {

    private final SanitizedLogger log = new SanitizedLogger("WafService");

    @Autowired
    private       WafDao                             wafDao              = null;
    @Autowired
    private       WafTypeDao                         wafTypeDao          = null;
    @Autowired
    private       WafRuleDao                         wafRuleDao          = null;
    @Autowired
    private       WafRuleDirectiveDao                wafRuleDirectiveDao = null;
    @Autowired
    private       VulnerabilityDao                   vulnerabilityDao    = null;
    private final RealTimeProtectionGeneratorFactory factory             = new RealTimeProtectionGeneratorFactory();

    @Override
    public List<Waf> loadAll() {
        return wafDao.retrieveAllActive();
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

            List<WafRule> wafRules = waf.getWafRules();

            if (wafRules != null) {
                for (WafRule rule : wafRules) {
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
    public List<WafRule> generateWafRules(Waf waf, WafRuleDirective directive, Application application) {
        if (waf == null || waf.getApplications() == null || waf.getApplications().size() == 0
				|| waf.getWafType() == null) {
			return null;
		}

		WafRuleDirective editedDirective = directive;

		if (editedDirective == null && waf.getLastWafRuleDirective() != null) {
			editedDirective = waf.getLastWafRuleDirective();
		}

        List<WafRule> newWafRuleList = null;
        RealTimeProtectionGenerator generator = factory.getTracker(waf.getWafType().getName());
		if (generator != null) {
			if (editedDirective == null) {
				editedDirective = generator.getDefaultDirective(waf);
			}

            newWafRuleList = generator.generateRules(waf, editedDirective, application);
            waf.addWafRules(newWafRuleList);
            waf.setLastWafRuleDirective(editedDirective);
			saveOrUpdateRules(waf, editedDirective);
			storeWaf(waf);
		}
        return newWafRuleList;
	}

    /**
     * Return updated rules for waf after generating new rules for application
     * @param waf
     * @param newWafRuleList
     * @return
     */
    private List<WafRule> getUpdatedWafRuleList(Waf waf, List<WafRule> newWafRuleList) {
        List<WafRule> oldList = waf.getWafRules();
        if (oldList == null || oldList.size() == 0)
            return newWafRuleList;
        if (newWafRuleList == null || newWafRuleList.size()==0)
            return oldList;
        int updatedAppId = newWafRuleList.get(0).getVulnerability().getApplication().getId();
        List<WafRule> removeList = list();
        for (WafRule rule : oldList) {
            if (rule.getVulnerability().getApplication().getId() == updatedAppId)
                removeList.add(rule);
//                oldList.remove(rule);
        }
        oldList.removeAll(removeList);
        oldList.addAll(newWafRuleList);
        return oldList;
    }


	@Override
	@Transactional(readOnly = false)
	public List<WafRule> generateWafRules(Waf waf, String directiveName, Application application) {
		if (waf == null || waf.getId() == null || waf.getWafType() == null 
				|| waf.getWafType().getId() == null)
			return null;
		WafRuleDirective directive = null;
		if (directiveName != null && !directiveName.isEmpty()) {
			WafRuleDirective tempDirective = wafRuleDirectiveDao.retrieveByWafTypeIdAndDirective(
														waf.getWafType(), directiveName);
			if (tempDirective != null)
				directive = tempDirective;
		}
		return generateWafRules(waf, directive, application);
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

        return getRulesText(waf, rules);
	}

    @Override
    public String getRulesText(Waf waf, List<WafRule> rules) {
        StringBuilder buffer = new StringBuilder();

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

    @Override
    public List<WafRule> getAppRules(Waf waf, Application application) {
        List<WafRule> allRules = loadCurrentRules(waf);
        if (waf==null || application == null)
            return allRules;
        List<WafRule> returnList = list();
        for (WafRule rule: allRules) {
            if (rule.getVulnerability().getApplication().getId()==application.getId())
                returnList.add(rule);
        }
        return returnList;
    }

}