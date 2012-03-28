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

import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.entities.Defect;

/**
 * Hibernate Defect DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateDefectDao implements DefectDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateDefectDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	public void deleteByApplicationId(Integer applicationId) {
		sessionFactory.getCurrentSession()
			.createQuery("update Vulnerability set defect = null where application = :appId")
			.setInteger("appId", applicationId)
			.executeUpdate();
		sessionFactory.getCurrentSession()
			.createQuery("delete Defect where application = :appId")
			.setInteger("appId", applicationId)
			.executeUpdate();
	}

	@Override
	public void deleteByDefectTrackerId(Integer defectTrackerId) {
		sessionFactory.getCurrentSession()
			.createQuery("update Vulnerability set defect = null where application in " +
					"(from Application where defectTracker = :defectTracker)")
			.setInteger("defectTracker", defectTrackerId)
			.executeUpdate();
		sessionFactory.getCurrentSession()
			.createQuery("delete Defect where application in " +
					"(from Application where defectTracker = :defectTracker)")
			.setInteger("defectTracker", defectTrackerId)
			.executeUpdate();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Defect> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from Defect defect order by defect.id").list();
	}

	@Override
	public Defect retrieveById(int id) {
		return (Defect) sessionFactory.getCurrentSession().get(Defect.class, id);
	}

	@Override
	public Defect retrieveByNativeId(String nativeId) {
		return (Defect) sessionFactory.getCurrentSession()
				.createQuery("from Defect defect where defect.nativeId = :nativeId")
				.setString("nativeId", nativeId).uniqueResult();
	}

	@Override
	public void saveOrUpdate(Defect defect) {
		sessionFactory.getCurrentSession().saveOrUpdate(defect);
	}

}
