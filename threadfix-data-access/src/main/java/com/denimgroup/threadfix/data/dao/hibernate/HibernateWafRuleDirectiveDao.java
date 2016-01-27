////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.dao.WafRuleDirectiveDao;
import com.denimgroup.threadfix.data.entities.WafRuleDirective;
import com.denimgroup.threadfix.data.entities.WafType;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

/**
 * Hibernate WafType DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractObjectDao
 */
@Repository
public class HibernateWafRuleDirectiveDao
        extends AbstractObjectDao<WafRuleDirective>
        implements WafRuleDirectiveDao {

    @Autowired
    public HibernateWafRuleDirectiveDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Order getOrder() {
        return Order.asc("wafRuleDirective");
    }

    @Override
    protected Class<WafRuleDirective> getClassReference() {
        return WafRuleDirective.class;
    }

	@Override
	public WafRuleDirective retrieveByWafTypeIdAndDirective(WafType wafType, String directive) {
		return (WafRuleDirective) sessionFactory.getCurrentSession()
				.createQuery("from WafRuleDirective wafRuleDirective where wafRuleDirective.wafType = :wafTypeId " +
						"and wafRuleDirective.directive = :directive")
				.setInteger("wafTypeId", wafType.getId()).setString("directive", directive).uniqueResult();
	}

}
