////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafRule;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;

/**
 * Hibernate WafRule DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateWafRuleDao implements WafRuleDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateWafRuleDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<WafRule> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from WafRule wafRule order by wafRule.id").list();
	}

	@Override
	public WafRule retrieveById(int id) {
		return (WafRule) sessionFactory.getCurrentSession().get(WafRule.class, id);
	}

	@Override
	public WafRule retrieveByRule(String rule) {
		return (WafRule) sessionFactory.getCurrentSession()
				.createQuery("from WafRule wafRule where wafRule.rule = :rule")
				.setString("rule", rule).uniqueResult();
	}

	@Override
	@Transactional(readOnly = false)
	public void saveOrUpdate(WafRule wafRule) {
		sessionFactory.getCurrentSession().saveOrUpdate(wafRule);
	}

	@Override
	public WafRule retrieveByWafAndNativeId(String wafId, String nativeId) {
		return (WafRule) sessionFactory.getCurrentSession()
			.createQuery("from WafRule wafRule where wafRule.nativeId = :nativeId and wafRule.waf = :wafId")
			.setString("nativeId", nativeId).setString("wafId", wafId).uniqueResult();
	}

	@Override
	public WafRule retrieveByVulnerabilityAndWafAndDirective(
			Vulnerability vuln, Waf waf, WafRuleDirective directive) {
		return (WafRule) sessionFactory
			.getCurrentSession()
			.createQuery( "from WafRule wafRule where wafRule.vulnerability = :vulnId " +
					"and wafRule.waf = :wafId and wafRule.wafRuleDirective = :directiveId")
			.setInteger("vulnId", vuln.getId()).setInteger("wafId", waf.getId())
			.setInteger("directiveId", directive.getId()).uniqueResult();
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<WafRule> retrieveByWafAndDirective(Waf waf,
			WafRuleDirective directive) {
		return (List<WafRule>) sessionFactory
			.getCurrentSession()
			.createQuery( "from WafRule wafRule where wafRule.waf = :wafId " +
				"and wafRule.wafRuleDirective = :directiveId")
			.setInteger("wafId", waf.getId())
			.setInteger("directiveId", directive.getId()).list();
	}


}
