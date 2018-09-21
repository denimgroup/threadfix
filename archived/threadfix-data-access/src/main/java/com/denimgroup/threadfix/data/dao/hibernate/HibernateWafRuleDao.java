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
package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.WafRuleDao;
import com.denimgroup.threadfix.data.entities.*;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate WafRule DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractObjectDao
 */
@Repository
public class HibernateWafRuleDao
        extends AbstractObjectDao<WafRule>
        implements WafRuleDao {

    @Autowired
    public HibernateWafRuleDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Order getOrder() {
        return Order.asc("id");
    }

    @Override
	public void delete(WafRule rule) {
		List<SecurityEvent> events = rule.getSecurityEvents();
		for (SecurityEvent event : events) {
			event.backUpWafRule();
			sessionFactory.getCurrentSession().save(event);
		}
		
		sessionFactory.getCurrentSession().save(new DeletedWafRule(rule));
		sessionFactory.getCurrentSession().delete(rule);
	}

	@Override
	public WafRule retrieveByRule(String rule) {
		return (WafRule) sessionFactory.getCurrentSession()
				.createQuery("from WafRule wafRule where wafRule.rule = :rule")
				.setString("rule", rule).uniqueResult();
	}

	@Override
	public WafRule retrieveByVulnerabilityAndWafAndDirective(
			Vulnerability vuln, Waf waf, WafRuleDirective directive) {
		return (WafRule) sessionFactory
				.getCurrentSession()
				.createQuery( "from WafRule wafRule where wafRule.vulnerability = :vulnId " +
						"and wafRule.waf = :wafId and wafRule.wafRuleDirective = :directiveId")
				.setInteger("vulnId", vuln.getId())
				.setInteger("wafId", waf.getId())
				.setInteger("directiveId", directive.getId())
				.setMaxResults(1).uniqueResult();
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<WafRule> retrieveByWafAndDirective(Waf waf,
			WafRuleDirective directive) {
		return sessionFactory
			.getCurrentSession()
			.createQuery( "from WafRule wafRule where wafRule.waf = :wafId " +
				"and wafRule.wafRuleDirective = :directiveId")
			.setInteger("wafId", waf.getId())
			.setInteger("directiveId", directive.getId()).list();
	}

	@Override
	public WafRule retrieveByWafAndNativeId(String wafId, String nativeId) {
		return (WafRule) sessionFactory.getCurrentSession()
			.createQuery("from WafRule wafRule where wafRule.nativeId = :nativeId and wafRule.waf = :wafId")
			.setString("nativeId", nativeId).setString("wafId", wafId).uniqueResult();
	}

    @Override
    protected Class<WafRule> getClassReference() {
        return WafRule.class;
    }


}
