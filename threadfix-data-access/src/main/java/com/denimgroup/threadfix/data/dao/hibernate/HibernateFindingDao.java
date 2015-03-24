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
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.entities.DeletedFinding;
import com.denimgroup.threadfix.data.entities.Finding;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Hibernate Finding DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 * 
 */
@Repository
public class HibernateFindingDao
        extends AbstractObjectDao<Finding>
        implements FindingDao {

	@Autowired
	public HibernateFindingDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<String> retrieveByHint(String hint, Integer appId) {
		Session currentSession = sessionFactory.getCurrentSession();
		Integer channelTypeId = (Integer) currentSession.createQuery(
				"select id from ChannelType where name = 'Manual'")
				.uniqueResult();
		if (channelTypeId == null) {
            assert false : "ThreadFix was unable to find the manual channel. This indicates an incomplete database connection.";
			return null;
        }
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
    protected Class<Finding> getClassReference() {
        return Finding.class;
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
	
	// While we could probably combine these queries, the resulting subquery would be very complicated.
	@SuppressWarnings("unchecked")
	public Criteria getScanIdAndPageCriteria(Integer scanId, int page) {
		
		List<Integer> mappedFindingIds = (List<Integer>) sessionFactory.getCurrentSession()
				.createQuery("select finding.id from ScanRepeatFindingMap map " +
						"where map.scan.id = :scanId")
				.setInteger("scanId", scanId)
				.list(); 
				
		Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.add(Restrictions.eq("active", true));
		
		if (mappedFindingIds != null && !mappedFindingIds.isEmpty()) {
			criteria.add(Restrictions.or(
					Restrictions.eq("scan.id", scanId),
					Restrictions.in("id", mappedFindingIds))
			);
		} else {
			criteria.add(Restrictions.eq("scan.id", scanId));
		}
				
		return criteria.createAlias("channelSeverity", "severity")
				.createAlias("channelVulnerability", "vuln")
				.createAlias("surfaceLocation", "surface")
				.setFirstResult((page - 1) * Finding.NUMBER_ITEM_PER_PAGE).setMaxResults(Finding.NUMBER_ITEM_PER_PAGE)
				.addOrder(Order.desc("severity.numericValue"))
				.addOrder(Order.asc("vuln.name"))
				.addOrder(Order.asc("surface.path"));
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<String> retrieveManualUrls(Integer appId) {
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
								+ "(select surfaceLocationId from Finding where scanId = :scanId) "
								+ "order by path")
				.setInteger("scanId", scanId).list();
	}

    @Override
    @SuppressWarnings("unchecked")
    public List<Finding> retrieveUnmappedFindingsByPage(int page, Integer appId) {
        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Finding.class)
                .add(Restrictions.eq("active", true))
                .add(Restrictions.isNull("vulnerability"));

        if (appId != null) {
            criteria.createAlias("scan", "scanAlias")
                    .createAlias("scanAlias.application", "appAlias")
                    .add(Restrictions.eq("appAlias.id", appId));
        }

        return criteria.createAlias("channelSeverity", "severity")
                .createAlias("channelVulnerability", "vuln")
                .createAlias("surfaceLocation", "surface")
                .setFirstResult((page - 1) * Finding.NUMBER_ITEM_PER_PAGE)
                .setMaxResults(Finding.NUMBER_ITEM_PER_PAGE)
                .addOrder(Order.desc("severity.numericValue"))
                .addOrder(Order.asc("vuln.name"))
                .addOrder(Order.asc("surface.path"))
                .list();
    }

	@SuppressWarnings("unchecked")
	@Override
	public List<Finding> retrieveByChannelVulnerabilityAndApplication(Integer channelVulnerabilityId, Integer applicationId) {
		return (List<Finding>) getSession()
				.createCriteria(Finding.class)
				.createAlias("channelVulnerability", "typeAlias")
				.createAlias("scan", "scanAlias")
				.createAlias("scanAlias.application", "applicationAlias")
				.add(Restrictions.eq("applicationAlias.id", applicationId))
				.add(Restrictions.eq("typeAlias.id", channelVulnerabilityId))
				.list();
	}

	@Override
	public long getTotalUnmappedFindings() {
		Long maybeLong = (Long) sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.add(Restrictions.eq("active", true))
				.add(Restrictions.isNull("vulnerability"))
				.setProjection(Projections.rowCount())
				.uniqueResult();
		return maybeLong == null ? 0 : maybeLong;
	}
}
