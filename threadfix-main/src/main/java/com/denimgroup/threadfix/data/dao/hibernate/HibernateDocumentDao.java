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
package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.DocumentDao;
import com.denimgroup.threadfix.data.entities.Document;

/**
 * Hibernate Document DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author stran
 * @see AbstractGenericDao
 */
@Repository
public class HibernateDocumentDao implements DocumentDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateDocumentDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public void saveOrUpdate(Document document) {
		if (document != null && document.getId() != null) {
			sessionFactory.getCurrentSession().merge(document);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(document);
		}
	}

	@Override
	public Document retrieveById(Integer docId) {
		return (Document) sessionFactory.getCurrentSession().get(Document.class, docId);
	}
	
	/**
	 * TODO - Clean up the way we're using this because this should currently only be used for
	 * ScanAgent configuration storage, and that is kind of a misuse of the Document object.
	 * 
	 * @param appId
	 * @param filename
	 * @param extension
	 * @return
	 */
	@Override
	public Document retrieveByAppIdAndFilename(Integer appId, String filename, String extension) {
		Document retVal;
		
		retVal = (Document) sessionFactory
				.getCurrentSession()
				.createQuery(
						"from Document document "
								+ "where document.application.id = :appId and document.name = :name and document.type = :type")
				.setInteger("appId", appId).setString("name", filename).setString("type", extension)
                .setMaxResults(1)
				.uniqueResult();

		return retVal;
	}

	@Override
	public void delete(Document document) {
		sessionFactory.getCurrentSession().delete(document);
		
	}

}
