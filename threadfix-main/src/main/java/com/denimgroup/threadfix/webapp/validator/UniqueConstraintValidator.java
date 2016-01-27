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
package com.denimgroup.threadfix.webapp.validator;

import static org.hibernate.criterion.DetachedCriteria.forClass;
import static org.hibernate.criterion.Projections.count;
import static org.hibernate.criterion.Restrictions.eq;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

import org.apache.commons.lang.StringUtils;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.DetachedCriteria;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.hibernate3.HibernateTemplate;

public class UniqueConstraintValidator implements
		ConstraintValidator<Unique, String> {

	@Autowired
	private SessionFactory sessionFactory;

	private Class<?> entity;
	private String field;

	@Override
	public void initialize(Unique annotation) {
		this.entity = annotation.entity();
		this.field = annotation.field();
	}

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		// Not a good determination, why sessionFactory is null if
		// the username is valid?
		if (sessionFactory == null) {
			return true;
		}
		if (StringUtils.isEmpty(value)) {
			return false;
		}
		return query(value).intValue() == 0;
	}

	private Number query(String value) {
		HibernateTemplate template = new HibernateTemplate(sessionFactory);
		DetachedCriteria criteria = forClass(entity).add(eq(field, value))
				.setProjection(count(field));
		return (Number) template.findByCriteria(criteria).iterator().next();
	}

}
