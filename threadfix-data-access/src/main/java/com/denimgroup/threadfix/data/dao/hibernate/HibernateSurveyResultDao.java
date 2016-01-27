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

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.SurveyResultDao;
import com.denimgroup.threadfix.data.entities.SurveyResult;

/**
 * Hibernate SurveyResult DAO implementation. Most basic methods are implemented
 * in the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateSurveyResultDao implements SurveyResultDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateSurveyResultDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<SurveyResult> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from SurveyResult surveyResult order by surveyResult.name").list();
	}

	@Override
	public SurveyResult retrieveById(int id) {
		return (SurveyResult) sessionFactory.getCurrentSession().get(SurveyResult.class, id);
	}

	@Override
	public SurveyResult retrieveByName(String name) {
		return (SurveyResult) sessionFactory.getCurrentSession()
				.createQuery("from SurveyResult surveyResult where surveyResult.name = :name")
				.setString("name", name).uniqueResult();
	}

	@Override
	public void saveOrUpdate(SurveyResult surveyResult) {
		sessionFactory.getCurrentSession().saveOrUpdate(surveyResult);
	}

}
