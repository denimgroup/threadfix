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

import java.util.List;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.entities.DeletedFinding;
import com.denimgroup.threadfix.data.entities.Finding;

/**
 * Hibernate Finding DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 * @author dwolf
 * @see AbstractGenericDao
 */
@Repository
public class HibernateFindingDao implements FindingDao {

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateFindingDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Finding> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from Finding finding order by finding.id").list();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<String> retrieveByHint(String hint, Integer appId) {
		Session currentSession = sessionFactory.getCurrentSession();
		Integer channelTypeId = (Integer) currentSession.createQuery(
				"select id from ChannelType where name = 'Manual'")
				.uniqueResult();
		if (channelTypeId == null)
			return null;
		Integer applicationChannelId = (Integer) (currentSession
				.createQuery(
						"select id from ApplicationChannel where applicationId = :appId and channelTypeId = :channelTypeId")
				.setInteger("appId", appId)
				.setInteger("channelTypeId", channelTypeId).uniqueResult());
		if (applicationChannelId == null)
			return null;
		Integer scanId = (Integer) currentSession
				.createQuery(
						"select id from Scan where applicationId = :appId and applicationChannelId = :applicationChannelId")
				.setInteger("appId", appId)
				.setInteger("applicationChannelId", applicationChannelId)
				.uniqueResult();
		if (scanId == null)
			return null;
		return currentSession
				.createSQLQuery(
						"select distinct(path) from SurfaceLocation where id in "
								+ "(select surfaceLocationId from Finding where scanId = :scanId) and path like "
								+ ":hint order by path")
				.setString("hint", "%" + hint + "%")
				.setInteger("scanId", scanId).list();
	}

	@Override
	public Finding retrieveById(int id) {
		return (Finding) sessionFactory.getCurrentSession().get(Finding.class,
				id);
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Finding> retrieveLatestDynamicByAppAndUser(int appId, int userId) {
		Session currentSession = sessionFactory.getCurrentSession();
		Integer channelTypeId = (Integer) currentSession.createQuery(
				"select id from ChannelType where name = 'Manual'")
				.uniqueResult();
		Integer applicationChannelId = (Integer) currentSession
				.createQuery(
						"select id from ApplicationChannel where applicationId = :appId and channelTypeId = :channelTypeId")
				.setInteger("appId", appId)
				.setInteger("channelTypeId", channelTypeId).uniqueResult();
		if (applicationChannelId == null)
			return null;
		Integer scanId = (Integer) currentSession
				.createQuery(
						"select id from Scan where applicationId = :appId and applicationChannelId = :applicationChannelId")
				.setInteger("appId", appId)
				.setInteger("applicationChannelId", applicationChannelId)
				.uniqueResult();
		if (scanId == null)
			return null;
		return currentSession
				.createQuery(
						"from Finding where scanId = :scanId and userId = :userId and isStatic = 0 order by createdDate desc")
				.setInteger("scanId", scanId).setInteger("userId", userId)
				.setMaxResults(10).list();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Finding> retrieveLatestStaticByAppAndUser(int appId, int userId) {
		Session currentSession = sessionFactory.getCurrentSession();
		Integer channelTypeId = (Integer) currentSession.createQuery(
				"select id from ChannelType where name = 'Manual'")
				.uniqueResult();
		Integer applicationChannelId = (Integer) currentSession
				.createQuery(
						"select id from ApplicationChannel where applicationId = :appId and channelTypeId = :channelTypeId")
				.setInteger("appId", appId)
				.setInteger("channelTypeId", channelTypeId).uniqueResult();
		if (applicationChannelId == null)
			return null;
		Integer scanId = (Integer) currentSession
				.createQuery(
						"select id from Scan where applicationId = :appId and applicationChannelId = :applicationChannelId")
				.setInteger("appId", appId)
				.setInteger("applicationChannelId", applicationChannelId)
				.uniqueResult();
		if (scanId == null)
			return null;
		return currentSession
				.createQuery(
						"from Finding where scanId = :scanId and userId = :userId and isStatic = 1 order by createdDate desc")
				.setInteger("scanId", scanId).setInteger("userId", userId)
				.setMaxResults(10).list();
	}

	@Override
	public void saveOrUpdate(Finding finding) {
		if (finding != null && finding.getId() != null) {
			sessionFactory.getCurrentSession().merge(finding);
		} else {
			sessionFactory.getCurrentSession().saveOrUpdate(finding);
		}
	}

	@Override
	public void delete(Finding finding) {
		sessionFactory.getCurrentSession().save(new DeletedFinding(finding));
		sessionFactory.getCurrentSession().delete(finding);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<Finding> retrieveFindingsByScanIdAndPage(Integer scanId,
			int page) {
		return getScanIdAndPageCriteria(scanId, page)
				.add(Restrictions.isNotNull("vulnerability"))
				.list();
	}

	@Override
	public Object retrieveUnmappedFindingsByScanIdAndPage(Integer scanId,
			int page) {
		return getScanIdAndPageCriteria(scanId, page)
				.add(Restrictions.isNull("vulnerability"))
				.list();
	}
	
	public Criteria getScanIdAndPageCriteria(Integer scanId, int page) {
		return sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.add(Restrictions.eq("active", true))
				.add(Restrictions.eq("scan.id", scanId))
				.createAlias("channelSeverity", "severity")
				.createAlias("channelVulnerability", "vuln")
				.createAlias("surfaceLocation", "surface")
				.setFirstResult((page - 1) * 100).setMaxResults(100)
				.addOrder(Order.desc("severity.numericValue"))
				.addOrder(Order.asc("vuln.name"))
				.addOrder(Order.asc("surface.path"));
	}
}
