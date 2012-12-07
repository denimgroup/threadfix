////////////////////////////////////////////////////////////////////////
//
//Copyright (c) 2009-2012 Denim Group, Ltd.
//
//The contents of this file are subject to the Mozilla Public License
//Version 1.1 (the "License"); you may not use this file except in
//compliance with the License. You may obtain a copy of the License at
//http://www.mozilla.org/MPL/
//
//Software distributed under the License is distributed on an "AS IS"
//basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//License for the specific language governing rights and limitations
//under the License.
//
//The Original Code is Vulnerability Manager.
//
//The Initial Developer of the Original Code is Denim Group, Ltd.
//Portions created by Denim Group, Ltd. are Copyright (C)
//Denim Group, Ltd. All Rights Reserved.
//
//Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.dao.hibernate;

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;

/**
 * Hibernate WafType DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateWafRuleDirectiveDao implements WafRuleDirectiveDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateWafRuleDirectiveDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<WafRuleDirective> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from WafRuleDirective wafRuleDirective order by wafRuleDirective").list();
	}

	@Override
	public WafRuleDirective retrieveById(int id) {
		return (WafRuleDirective) sessionFactory.getCurrentSession().get(WafRuleDirective.class, id);
	}

	@Override
	public WafRuleDirective retrieveByWafTypeIdAndDirective(WafType wafType, String directive) {
		return (WafRuleDirective) sessionFactory.getCurrentSession()
				.createQuery("from WafRuleDirective wafRuleDirective where wafRuleDirective.wafType = :wafTypeId " +
						"and wafRuleDirective.directive = :directive")
				.setInteger("wafTypeId", wafType.getId()).setString("directive", directive).uniqueResult();
	}

}
