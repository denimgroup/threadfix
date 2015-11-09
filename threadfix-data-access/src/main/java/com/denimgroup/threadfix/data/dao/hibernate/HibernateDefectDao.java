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
import com.denimgroup.threadfix.data.dao.DefectDao;
import com.denimgroup.threadfix.data.dao.EventDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.DeletedDefect;
import com.denimgroup.threadfix.data.entities.Event;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate Defect DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author mcollins, dwolf
 * @see AbstractObjectDao
 */
@Repository
public class HibernateDefectDao
        extends AbstractObjectDao<Defect>
        implements DefectDao {

	@Autowired
	public HibernateDefectDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Autowired
	private EventDao eventDao;

	// TODO keep track of the vulns that were associated with each Defect
	@SuppressWarnings("unchecked")
	@Override
	public void deleteByApplicationId(Integer applicationId) {
		for (Defect defect : retrieveAllActive()) {
			sessionFactory.getCurrentSession().save(new DeletedDefect(defect));
		}

		sessionFactory.getCurrentSession()
				.createQuery("update Vulnerability set defectId = null where applicationId = :appId")
				.setInteger("appId", applicationId)
				.executeUpdate();
		sessionFactory.getCurrentSession()
				.createQuery("update Vulnerability set vulnerabilityDefectConsistencyState = null where application = :appId")
				.setInteger("appId", applicationId)
				.executeUpdate();
		sessionFactory.getCurrentSession().createQuery("update Event set defectId = null where applicationId = :appId")
				.setInteger("appId", applicationId)
				.executeUpdate();
		sessionFactory.getCurrentSession().createQuery("delete from Defect where application = :appId")
				.setInteger("appId", applicationId)
				.executeUpdate();
	}

	// TODO keep track of the vulns that were associated with each Defect
	@SuppressWarnings("unchecked")
	@Override
	public void deleteByDefectTrackerId(Integer defectTrackerId) {
		sessionFactory.getCurrentSession()
			.createQuery("update Vulnerability set defect = null where application in " +
					"(from Application where defectTracker = :defectTracker)")
			.setInteger("defectTracker", defectTrackerId)
			.executeUpdate();
		
		List<Defect> defects = ((List<Defect>) sessionFactory.getCurrentSession()
				.createQuery("from Defect where application in " +
						"(from Application where defectTracker = :defectTracker)")
				.setInteger("defectTracker", defectTrackerId)
				.list());
			
		if (defects != null && defects.size() > 0) {
			for (Defect defect : defects) {
				for (Event event: defect.getEvents()) {
					event.setDefect(null);
					eventDao.saveOrUpdate(event);
				}
				delete(defect);
			}
		}
	}

	@Override
	public Defect retrieveByNativeId(String nativeId) {
		return (Defect) sessionFactory.getCurrentSession()
				.createQuery("from Defect defect where defect.nativeId = :nativeId")
				.setString("nativeId", nativeId).uniqueResult();
	}

    @Override
    protected Class<Defect> getClassReference() {
        return Defect.class;
    }

    @Override
	public void delete(Defect defect) {

		for (Event event: defect.getEvents()) {
			event.setDefect(null);
			eventDao.saveOrUpdate(event);
		}

		sessionFactory.getCurrentSession().save(new DeletedDefect(defect));
		sessionFactory.getCurrentSession().delete(defect);
	}
}
