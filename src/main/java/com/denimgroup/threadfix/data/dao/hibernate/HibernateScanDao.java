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
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.DeletedDataFlowElement;
import com.denimgroup.threadfix.data.entities.DeletedFinding;
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

	private SessionFactory sessionFactory;

	@Autowired
	public HibernateScanDao(SessionFactory sessionFactory) {
		this.sessionFactory = sessionFactory;
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
			.createQuery("from Scan scan where scan.application.id in (:idList)").setParameterList("idList", applicationIdList).list();
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
		sessionFactory.getCurrentSession().delete(scan);
	}

	@Override
	public void deleteMap(ScanCloseVulnerabilityMap map) {
		sessionFactory.getCurrentSession().delete(map);
	}

	@Override
	public void deleteMap(ScanReopenVulnerabilityMap map) {
		sessionFactory.getCurrentSession().delete(map);
	}

	@Override
	public void deleteMap(ScanRepeatFindingMap map) {
		sessionFactory.getCurrentSession().delete(map);
	}
	
	@Override
	public long getFindingCount(Integer scanId) {
		return (Long) sessionFactory.getCurrentSession()
							 .createCriteria(Finding.class)
							 .setProjection(Projections.rowCount())
							 .add(Restrictions.isNotNull("vulnerability"))
							 .add(Restrictions.eq("scan.id", scanId))
							 .uniqueResult();
	}
	
	@Override
	public long getFindingCountUnmapped(Integer scanId) {
		return (Long) sessionFactory.getCurrentSession()
							 .createCriteria(Finding.class)
							 .setProjection(Projections.rowCount())
							 .add(Restrictions.eq("scan.id", scanId))
							 .add(Restrictions.isNull("vulnerability"))
							 .uniqueResult();

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
		
		response = (Long) sessionFactory.getCurrentSession()
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
		if (scan == null) 
			return;
		
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
	
}
