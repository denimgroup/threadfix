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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Order;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.DeletedCloseMap;
import com.denimgroup.threadfix.data.entities.DeletedDataFlowElement;
import com.denimgroup.threadfix.data.entities.DeletedFinding;
import com.denimgroup.threadfix.data.entities.DeletedReopenMap;
import com.denimgroup.threadfix.data.entities.DeletedRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.DeletedScan;
import com.denimgroup.threadfix.data.entities.DeletedSurfaceLocation;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanCloseVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanReopenVulnerabilityMap;
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;

/**
 * Hibernate Scan DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author mcollins
 * @see AbstractGenericDao
 */
@Repository
public class HibernateScanDao implements ScanDao {
	
	private String selectStart = "(select count(*) from Vulnerability vulnerability where vulnerability.hidden = false and vulnerability.genericSeverity.intValue = ";
	private String idStart = "scan.id as id, ";
	private String vulnIds = " and vulnerability in (select finding.vulnerability.id from Finding finding where finding.scan = scan))";
	private String mapVulnIds = " and vulnerability in (select map.finding.vulnerability.id from ScanRepeatFindingMap map where map.scan = scan))";
	private String fromClause = "from Scan scan where scan.id = :scanId";

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateScanDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Map<String,Object> getFindingSeverityMap(Scan scan) {
		return (Map<String, Object>) sessionFactory.getCurrentSession().createQuery(
				"select new map( " +
						idStart +
						selectStart + "1" + vulnIds + " as info, " +
						selectStart + "2" + vulnIds + " as low, " +
						selectStart + "3" + vulnIds + " as medium, " +
						selectStart + "4" + vulnIds + " as high, " +
						selectStart + "5" + vulnIds + " as critical) " +
						fromClause
				).setInteger("scanId", scan.getId()).uniqueResult();
	}

	@SuppressWarnings("unchecked")
	@Override
	public Map<String,Object> getMapSeverityMap(Scan scan) {
		return (Map<String, Object>) sessionFactory.getCurrentSession().createQuery(
				"select new map( " +
						idStart +
						selectStart + "1" + mapVulnIds + " as info, " +
						selectStart + "2" + mapVulnIds + " as low, " +
						selectStart + "3" + mapVulnIds + " as medium, " +
						selectStart + "4" + mapVulnIds + " as high, " +
						selectStart + "5" + mapVulnIds + " as critical) " +
						fromClause
				).setInteger("scanId", scan.getId()).uniqueResult();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> retrieveAll() {
		return sessionFactory.getCurrentSession()
				.createQuery("from Scan scan order by scan.importTime desc").list();
	}

	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> retrieveByApplicationIdList(List<Integer> applicationIdList) {
		return sessionFactory.getCurrentSession()
			.createQuery("from Scan scan where scan.application.id in (:idList)")
			.setParameterList("idList", applicationIdList)
			.list();
	}
	
	@Override
	public Scan retrieveById(int id) {
		return (Scan) sessionFactory.getCurrentSession().get(Scan.class, id);
	}

	@Override
	@Transactional
	public void saveOrUpdate(Scan scan) {
		sessionFactory.getCurrentSession().saveOrUpdate(scan);
	}
	
	@Override
	public void delete(Scan scan) {
		sessionFactory.getCurrentSession().save(new DeletedScan(scan));
		sessionFactory.getCurrentSession().delete(scan);
	}

	@Override
	public void deleteMap(ScanCloseVulnerabilityMap map) {
		sessionFactory.getCurrentSession().save(new DeletedCloseMap(map));
		sessionFactory.getCurrentSession().delete(map);
	}

	@Override
	public void deleteMap(ScanReopenVulnerabilityMap map) {
		sessionFactory.getCurrentSession().save(new DeletedReopenMap(map));
		sessionFactory.getCurrentSession().delete(map);
	}

	@Override
	public void deleteMap(ScanRepeatFindingMap map) {
		sessionFactory.getCurrentSession().save(new DeletedRepeatFindingMap(map));
		sessionFactory.getCurrentSession().delete(map);
	}
	
	@Override
	public long getFindingCount(Integer scanId) {
		Long actualFindings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(Finding.class)
			 .add(Restrictions.isNotNull("vulnerability"))
			 .add(Restrictions.eq("scan.id", scanId))
			 .setProjection(Projections.rowCount())
			 .uniqueResult();
		
		Long mappings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(ScanRepeatFindingMap.class)
			 .createAlias("finding", "finding")
			 .add(Restrictions.isNotNull("finding.vulnerability"))
			 .add(Restrictions.eq("scan.id", scanId))
			 .setProjection(Projections.rowCount())
			 .uniqueResult();
		
		return actualFindings + mappings;
	}
	
	@Override
	public long getFindingCountUnmapped(Integer scanId) {
		Long actualFindings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(Finding.class)
			 .add(Restrictions.isNull("vulnerability"))
			 .add(Restrictions.eq("scan.id", scanId))
			 .setProjection(Projections.rowCount())
			 .uniqueResult();
		
		Long mappings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(ScanRepeatFindingMap.class)
			 .createAlias("finding", "finding")
			 .add(Restrictions.isNull("finding.vulnerability"))
			 .add(Restrictions.eq("scan.id", scanId))
			 .setProjection(Projections.rowCount())
			 .uniqueResult();
		
		return actualFindings + mappings;

	}
	
	// These should probably be saved in the scans and then updated when necessary (scan deletions, database updates)
	// That could be messy but querying the database every time is not absolutely necessary.

	@Override
	public long getTotalNumberSkippedResults(Integer scanId) {
		Object response = sessionFactory.getCurrentSession()
										 .createQuery("select sum( finding.numberMergedResults ) " +
										 		"from Finding finding where scan = :scan")
										 .setInteger("scan", scanId)
										 .uniqueResult();
		long totalMergedResults = 0, totalResults = 0;
		if (response != null) {
			totalMergedResults = (Long) response;
		}
		
		response = sessionFactory.getCurrentSession()
										 .createQuery("select count(*) from Finding finding where scan = :scan")
										 .setInteger("scan", scanId)
										 .uniqueResult();
		
		if (response != null) {
			totalResults = (Long) response;
		}
		
		return totalMergedResults - totalResults;
	}

	@Override
	public long getNumberWithoutChannelVulns(Integer scanId) {
		return (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .add(Restrictions.isNull("channelVulnerability"))
				 .add(Restrictions.eq("scan.id", scanId))
				 .setProjection(Projections.rowCount())
				 .uniqueResult();
	}

	@Override
	public long getNumberWithoutGenericMappings(Integer scanId) {
		return (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .createAlias("channelVulnerability", "vuln")
				 .add(Restrictions.isEmpty( "vuln.vulnerabilityMaps" ))
				 .add(Restrictions.eq("scan.id", scanId))
				 .setProjection(Projections.rowCount())
				 .uniqueResult();
	}
	
	@Override
	public long getTotalNumberFindingsMergedInScan(Integer scanId) {
		long numUniqueVulnerabilities = (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .createAlias("vulnerability", "vuln")
				 .add(Restrictions.eq("scan.id", scanId))
				 .setProjection(Projections.countDistinct("vuln.id"))
				 .uniqueResult();
		
		long numFindingsWithVulnerabilities = (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .add(Restrictions.isNotNull("vulnerability"))
				 .add(Restrictions.eq("scan.id", scanId))
				 .setProjection(Projections.rowCount())
				 .uniqueResult();
		
		return numFindingsWithVulnerabilities - numUniqueVulnerabilities;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public void deleteFindingsAndScan(Scan scan) {
		if (scan == null) {
			return;
		}
		
		List<Long> surfaceLocationIds = sessionFactory.getCurrentSession()
				  	  .createQuery("select surfaceLocation.id from Finding where scan = :scan)")
					  .setInteger("scan", scan.getId())
					  .list();
		
		List<DataFlowElement> dataFlowElements = sessionFactory.getCurrentSession()
					  .createQuery("from DataFlowElement element " +
					  		"where element.finding in (select id from Finding where scan = :scan)")
					  .setInteger("scan", scan.getId())
					  .list();
				
		for (DataFlowElement dataFlowElement : dataFlowElements) {
			sessionFactory.getCurrentSession().save(new DeletedDataFlowElement(dataFlowElement));
			sessionFactory.getCurrentSession().delete(dataFlowElement);
		}
		
		List<SurfaceLocation> surfaceLocations = null;
		
		if (surfaceLocationIds != null && surfaceLocationIds.size() > 0) {
			surfaceLocations = sessionFactory.getCurrentSession()
						  .createQuery("from SurfaceLocation " +
						  		"where id in (:ids)")
						  .setParameterList("ids", surfaceLocationIds)
						  .list();
			
			for (SurfaceLocation surfaceLocation : surfaceLocations) {
				sessionFactory.getCurrentSession().save(new DeletedSurfaceLocation(surfaceLocation));
			}
		}
		
		List<Finding> findings = sessionFactory.getCurrentSession()
			  	  .createQuery("from Finding where scan = :scan)")
				  .setInteger("scan", scan.getId())
				  .list();
		
		for (Finding finding : findings) {
			sessionFactory.getCurrentSession().save(new DeletedFinding(finding));
			sessionFactory.getCurrentSession().delete(finding);
		}
		
		findings = null;

		if (surfaceLocations != null) {
			for (SurfaceLocation surfaceLocation : surfaceLocations) {
				sessionFactory.getCurrentSession().delete(surfaceLocation);
			}
		}
		
		sessionFactory.getCurrentSession().save(new DeletedScan(scan));
		sessionFactory.getCurrentSession().delete(scan);
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public Map<String, Object> getCountsForScans(List<Integer> ids) {
		if (ids == null || ids.isEmpty()) {
			return new HashMap<>();
		}
		
		String selectStart = "(select count(*) from Vulnerability vulnerability where vulnerability.isFalsePositive = false and vulnerability.hidden = false and " +
				"(vulnerability.active = true OR vulnerability.foundByScanner = true) AND " +
				"(vulnerability.genericSeverity.intValue = ";
		String vulnIds = " and (vulnerability in (select finding.vulnerability.id from Finding finding where finding.vulnerability.hidden = false and finding.scan.id in ";
		String orMapIds = " or vulnerability in (select map.finding.vulnerability.id from ScanRepeatFindingMap map where map.finding.vulnerability.hidden = false and map.scan.id in ";

		return (Map<String, Object>) sessionFactory.getCurrentSession().createQuery(
				"select new map( scan.id as id, " +
						selectStart + "1" + vulnIds + "(:scanIds1))" + orMapIds + "(:scanIds12))))) as info, " +
						selectStart + "2" + vulnIds + "(:scanIds2))" + orMapIds + "(:scanIds22))))) as low, " +
						selectStart + "3" + vulnIds + "(:scanIds3))" + orMapIds + "(:scanIds32))))) as medium, " +
						selectStart + "4" + vulnIds + "(:scanIds4))" + orMapIds + "(:scanIds42))))) as high, " +
						selectStart + "5" + vulnIds + "(:scanIds5))" + orMapIds + "(:scanIds52))))) as critical)" +
						" from Scan scan where scan.id = :scanId"
				)
				.setParameterList("scanIds1", ids)
				.setParameterList("scanIds2", ids)
				.setParameterList("scanIds3", ids)
				.setParameterList("scanIds4", ids)
				.setParameterList("scanIds5", ids)
				.setParameterList("scanIds12", ids)
				.setParameterList("scanIds22", ids)
				.setParameterList("scanIds32", ids)
				.setParameterList("scanIds42", ids)
				.setParameterList("scanIds52", ids)
				.setInteger("scanId", ids.get(0))
				.uniqueResult();
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<Scan> retrieveMostRecent(int number, Set<Integer> authenticatedAppIds,
			Set<Integer> authenticatedTeamIds) {

		Criteria baseCriteria = getBaseScanCriteria()
				.addOrder(Order.desc("id"))
				.setMaxResults(number);
		
		Criteria result = addFiltering(baseCriteria, authenticatedTeamIds, authenticatedAppIds);
		
		if (result == null) {
			return new ArrayList<>();
		} else {
			return baseCriteria.list();
		}
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public List<Scan> retrieveMostRecent(int number) {
		return getBaseScanCriteria()
				.addOrder(Order.desc("id"))
				.setMaxResults(number)
				.list();
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> getTableScans(Integer page) {

		return getBaseScanCriteria()
			.setFirstResult((page - 1) * 100)
			.setMaxResults(100)
			.addOrder(Order.desc("importTime"))
			.list();
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public List<Scan> getTableScans(Integer page, Set<Integer> authenticatedAppIds, Set<Integer> authenticatedTeamIds) {
		
		Criteria criteria = getBaseScanCriteria()
			.setFirstResult((page - 1) * 100)
			.setMaxResults(100)
			.addOrder(Order.desc("importTime"));
		
		Criteria filteredCriteria = addFiltering(criteria, authenticatedTeamIds, authenticatedAppIds);
		
		if (filteredCriteria == null) {
			return new ArrayList<>();
		} else {
			return criteria.list();
		}
	}
	
	@Override
	public int getScanCount() {

		Long result = (Long) getBaseScanCriteria()
			.setProjection(Projections.rowCount())
			.uniqueResult();
		
		return safeLongToInt(result);
	}
	
	@Override
	public int getScanCount(Set<Integer> authenticatedAppIds, Set<Integer> authenticatedTeamIds) {

		Criteria criteria = getBaseScanCriteria()
			.setProjection(Projections.rowCount());
		
		
		Criteria filteredCriteria = addFiltering(criteria, authenticatedTeamIds, authenticatedAppIds);
		
		if (filteredCriteria == null) {
			return 0;
		} else {
			return safeLongToInt((Long) filteredCriteria.uniqueResult());
		}
	}
	
	private Criteria getBaseScanCriteria() {
		return sessionFactory.getCurrentSession()
				.createCriteria(Scan.class)
				.createAlias("application", "app")
				.add(Restrictions.eq("app.active", true));
	}
	
	private Criteria addFiltering(Criteria criteria, Set<Integer> teamIds, Set<Integer> appIds) {
		
		boolean useAppIds = appIds != null && !appIds.isEmpty(),
				useTeamIds = teamIds != null && !teamIds.isEmpty();
		
		if (!useAppIds && !useTeamIds) {
			return null;
		}
		
		if (useAppIds && useTeamIds) {
			criteria.createAlias("app.organization", "team")
				.add(Restrictions.eq("team.active", true))
				.add(Restrictions.or(
						Restrictions.in("app.id", appIds),
						Restrictions.in("team.id", teamIds)
						));
		} else if (useAppIds) {
			criteria
				.add(Restrictions.in("app.id", appIds));
		} else {
			criteria.createAlias("app.organization", "team")
				.add(Restrictions.in("team.id", teamIds))
				.add(Restrictions.eq("team.active", true));
		}
		return criteria;
	}
	
	private static int safeLongToInt(long l) {
		if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		return (int) l;
	}
}
