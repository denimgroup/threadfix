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
import com.denimgroup.threadfix.data.dao.EventDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.*;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static org.hibernate.criterion.Projections.property;
import static org.hibernate.criterion.Projections.rowCount;
import static org.hibernate.criterion.Restrictions.*;

/**
 * Hibernate Scan DAO implementation. Most basic methods are implemented in the
 * AbstractGenericDao
 * 
 * @author mcollins
 */
@Repository
public class HibernateScanDao
        extends AbstractObjectDao<Scan>
        implements ScanDao {

	@Autowired
	EventDao eventDao;

	@Autowired
	public HibernateScanDao(SessionFactory sessionFactory) {
		super(sessionFactory);
	}

    @Override
    public void deleteScanFileLocations() {
		List<Scan> list = retrieveAll();
		for (Scan scan : list) {
			scan.setOriginalFileNames(null);
			scan.setSavedFileNames(null);
			scan.setFileName(null);
			saveOrUpdate(scan);
		}
    }

    @Override
    protected Order getOrder() {
        return Order.desc("importTime");
    }

    @Override
	@SuppressWarnings("unchecked")
	public List<Scan> retrieveByApplicationIdList(List<Integer> applicationIdList) {

		if (applicationIdList == null || applicationIdList.isEmpty()) {
			return list();
		}

		List<Integer> scanIds =  sessionFactory.getCurrentSession()
				.createCriteria(Application.class)
				.add(Restrictions.in("id", applicationIdList))
				.createAlias("scans", "scans")
				.add(Restrictions.eq("scans.lockedMetadata", false))
				.setProjection(Projections.groupProperty("scans.id"))
				.list();

		if (scanIds != null && !scanIds.isEmpty()) {
			return sessionFactory.getCurrentSession()
					.createCriteria(Scan.class)
					.add(Restrictions.in("id", scanIds))
					.list();
		} else {
			return list();
		}

	}

    @Override
    protected Class<Scan> getClassReference() {
        return Scan.class;
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
			 .add(eq("scan.id", scanId))
			 .setProjection(rowCount())
			 .uniqueResult();
		
		Long mappings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(ScanRepeatFindingMap.class)
			 .createAlias("finding", "finding")
			 .add(Restrictions.isNotNull("finding.vulnerability"))
			 .add(eq("scan.id", scanId))
			 .setProjection(rowCount())
			 .uniqueResult();
		
		return actualFindings + mappings;
	}
	
	@Override
	public long getFindingCountUnmapped(Integer scanId) {
		Long actualFindings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(Finding.class)
			 .add(isNull("vulnerability"))
			 .add(eq("scan.id", scanId))
			 .setProjection(rowCount())
			 .uniqueResult();
		
		Long mappings = (Long) sessionFactory.getCurrentSession()
			 .createCriteria(ScanRepeatFindingMap.class)
			 .createAlias("finding", "finding")
			 .add(isNull("finding.vulnerability"))
			 .add(eq("scan.id", scanId))
			 .setProjection(rowCount())
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
				 .add(isNull("channelVulnerability"))
				 .add(eq("scan.id", scanId))
				 .setProjection(rowCount())
				 .uniqueResult();
	}

	@Override
	public long getNumberWithoutGenericMappings(Integer scanId) {
		return (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .createAlias("channelVulnerability", "vuln")
				 .add(Restrictions.isEmpty( "vuln.vulnerabilityMaps" ))
				 .add(eq("scan.id", scanId))
				 .setProjection(rowCount())
				 .uniqueResult();
	}
	
	@Override
	public long getTotalNumberFindingsMergedInScan(Integer scanId) {
		long numUniqueVulnerabilities = (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .createAlias("vulnerability", "vuln")
				 .add(eq("scan.id", scanId))
				 .setProjection(Projections.countDistinct("vuln.id"))
				 .uniqueResult();
		
		long numFindingsWithVulnerabilities = (Long) sessionFactory.getCurrentSession()
				 .createCriteria(Finding.class)
				 .add(Restrictions.isNotNull("vulnerability"))
				 .add(eq("scan.id", scanId))
				 .setProjection(rowCount())
				 .uniqueResult();
		
		return numFindingsWithVulnerabilities - numUniqueVulnerabilities;
	}
	
	@Override
	@SuppressWarnings("unchecked")
	public void deleteFindingsAndScan(Scan scan) {
		if (scan == null) {
			return;
		}
		
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
		
		surfaceLocations = sessionFactory.getCurrentSession()
					  .createQuery("from SurfaceLocation " +
							"where id in (select surfaceLocation.id from Finding where scan = :scan)")
					  .setInteger("scan", scan.getId())
					  .list();

		for (SurfaceLocation surfaceLocation : surfaceLocations) {
			sessionFactory.getCurrentSession().save(new DeletedSurfaceLocation(surfaceLocation));
		}

		// The following sections were moved from an aspect so that they're now in the same transaction

		for (Finding finding : scan.getFindings()) {
			for (Event event : eventDao.retrieveAllByFinding(finding)) {
				event.setFinding(null);
				eventDao.saveOrUpdate(event);
			}
		}

		for (Event event : listFrom(scan.getEvents())) {
			event.setDeletedScanId(scan.getId());
			event.setScan(null);
			scan.getEvents().remove(event);
			sessionFactory.getCurrentSession().save(event);
		}

		for (ScanCloseVulnerabilityMap map : listFrom(scan.getScanCloseVulnerabilityMaps())) {
			map.getVulnerability().getScanCloseVulnerabilityMaps().remove(map);
			scan.getScanCloseVulnerabilityMaps().remove(map);
			map.setVulnerability(null);
			map.setScan(null);
		}

		// end section from aspect

		List<Finding> findings = sessionFactory.getCurrentSession()
			  	  .createQuery("from Finding where scan = :scan")
				  .setInteger("scan", scan.getId())
				  .list();
		
		for (Finding finding : findings) {
			sessionFactory.getCurrentSession().save(new DeletedFinding(finding));
			sessionFactory.getCurrentSession().delete(finding);

			for (EndpointPermission endpointPermission : finding.getEndpointPermissions()) {
				endpointPermission.getFindingList().remove(finding);
				sessionFactory.getCurrentSession().save(endpointPermission);
			}

		}

		findings = null;

		if (surfaceLocations != null) {
			for (SurfaceLocation surfaceLocation : surfaceLocations) {
				sessionFactory.getCurrentSession().delete(surfaceLocation);
			}
		}

		delete(scan);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<Scan> retrieveMostRecent(int number, Set<Integer> authenticatedAppIds,
			Set<Integer> authenticatedTeamIds) {

		Criteria baseCriteria = getBaseScanCriteria()
				.addOrder(Order.desc("id"))
				.setMaxResults(number);
		
		Criteria result = addFiltering(baseCriteria, authenticatedTeamIds, authenticatedAppIds);
		
        return result.list();
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
        return filteredCriteria.list();
	}

	@Override
	public List<Scan> retrieveAll() {
		Criteria criteria = getBaseScanCriteria()
				.addOrder(getOrder());

		return criteria.list();
	}

	@Override
	public int getScanCount() {
		Long result = (Long) getBaseScanCriteria().setProjection(rowCount()).uniqueResult();
		
		return safeLongToInt(result);
	}
	
	@Override
	public int getScanCount(Set<Integer> authenticatedAppIds, Set<Integer> authenticatedTeamIds) {

		Criteria criteria = getBaseScanCriteria().setProjection(rowCount());
		
		Criteria filteredCriteria = addFiltering(criteria, authenticatedTeamIds, authenticatedAppIds);
		
        return safeLongToInt((Long) filteredCriteria.uniqueResult());
	}
	
	private Criteria getBaseScanCriteria() {
		return sessionFactory.getCurrentSession()
				.createCriteria(Scan.class)
				.createAlias("application", "app")
				.add(eq("app.active", true));
	}

    @Nonnull
	private Criteria addFiltering(Criteria criteria, Set<Integer> teamIds, Set<Integer> appIds) {
		
		boolean useAppIds = appIds != null,
				useTeamIds = teamIds != null;

        if (teamIds != null && teamIds.isEmpty()) {
            teamIds = set(0);
        }

        if (appIds != null && appIds.isEmpty()) {
            appIds = set(0);
        }

		if (!useAppIds && !useTeamIds) {
			return criteria;
		}
		
		if (useAppIds && useTeamIds) {
			criteria.createAlias("app.organization", "team")
				.add(eq("team.active", true))
				.add(or(
						Restrictions.in("app.id", appIds),
						Restrictions.in("team.id", teamIds)
				));
		} else if (useAppIds) {
			criteria
				.add(Restrictions.in("app.id", appIds));
		} else {
			criteria.createAlias("app.organization", "team")
				.add(Restrictions.in("team.id", teamIds))
				.add(eq("team.active", true));
		}
		return criteria;
	}
	
	private static int safeLongToInt(long l) {
		if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		return (int) l;
	}

    @Override
    @SuppressWarnings("unchecked")
    public List<String> loadScanFilenames() {
        return sessionFactory.getCurrentSession()
                .createQuery("select s.fileName from Scan s where s.fileName is not null").list();
    }

	@Override
	public List<Finding> getFindingsWithIds(List<Integer> findingIds) {

		if (findingIds == null || findingIds.isEmpty()) {
			return list();
		}

		return sessionFactory.getCurrentSession()
				.createCriteria(Finding.class)
				.add(isEmpty("statisticsCounters"))
				.add(in("id", findingIds))
				.list();
	}

	@Override
	public List<Integer> findingIdsThatNeedCounters(Collection<Integer> findingIdRestrictions) {

		List<Integer> findingIds = sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.createAlias("vulnerability", "vulnAlias")
				.createAlias("vulnAlias.application", "appAlias")
				.add(eq("appAlias.active", true))
				.add(isEmpty("statisticsCounters"))
				.setProjection(property("id"))
				.list();

		Set<Integer> restrictionSet = setFrom(findingIdRestrictions);
		Set<Integer> emptyStatsCountersTests = setFrom(findingIds);

		emptyStatsCountersTests.retainAll(restrictionSet);

		return listFrom(emptyStatsCountersTests);
	}

	@Override
	public List<Integer> findingIdsThatNeedCountersInApps(List<Integer> appIds, Collection<Integer> findingIdRestrictions) {
		if (appIds == null)
			return findingIdsThatNeedCounters(findingIdRestrictions);

		if (appIds.size() == 0) {
			return list();
		}

		List<Integer> findingIds = sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.createAlias("vulnerability", "vulnAlias")
				.createAlias("vulnAlias.application", "appAlias")
				.add(eq("appAlias.active", true))
				.add(in("appAlias.id", appIds))
				.add(isEmpty("statisticsCounters"))
				.setProjection(property("id"))
                .list();

		// these are IDs for findings that should have stats counters
		Set<Integer> findingIdRestrictionSet = setFrom(findingIdRestrictions);

		// these are IDs for findings that don't have stats counters
		Set<Integer> findingsWithEmptyStatsCounters = setFrom(findingIds);

		// this set should then be IDs for findings that don't have stats counters but should
		findingsWithEmptyStatsCounters.retainAll(findingIdRestrictionSet);

		return listFrom(findingsWithEmptyStatsCounters);
	}

	private Criteria getBaseCounterCriteria(List<Integer> appIds, Collection<Integer> findingIdRestrictions) {
		Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Finding.class)
				.createAlias("vulnerability", "vulnAlias")
				.createAlias("vulnAlias.application", "appAlias")
				.add(eq("appAlias.active", true))
				.add(isEmpty("statisticsCounters"));

        if (findingIdRestrictions != null && !findingIdRestrictions.isEmpty()) {
            criteria.add(in("id", findingIdRestrictions));
        }

        if (appIds != null && !appIds.isEmpty()) {
            criteria.add(in("appAlias.id", appIds));
        }
        return criteria;
	}

	@Override
	public List<ScanRepeatFindingMap> getMapsThatNeedCounters(int page) {
		return getBasicMapCriteria()
				.setMaxResults(100)
				.setFirstResult(page * 100)
				.list();
    }

    private Integer hashIt(Object date, Object second, Object third) {

        int result = date != null ? date.hashCode() : 0;
        result = 31 * result + (second instanceof Integer ? (Integer) second : 0);
        result = 31 * result + (third instanceof Integer ? (Integer) third : 0);
        return result;
    }

    /**
     * I want to get the earliest finding for each channeltype for each vulnerability
     * This solves the problem we had before where vulnerabilities with findings merged
     * over different scanners had incorrect statistics because firstFindingForVuln was used in stats
     * calculation
     *
     * This involves testing uniqueness over the following fields:
     *  - vuln ID
     *  - scan ID (time, so we can sort)
     *  - channel ID
     *
     * Then sort by date and take the earliest one. It will then go through another SQL statement
     * to make sure it's appropriate. We also need to cache this for multiple runs.
     *
     * Strategy-wise, we get all of these fields and hash them to create a key
     * This is a much smaller structure than hibernate objects. We want that to reduce the
     * memory footprint of this algorithm.
     *
     * With a caveat: some findings have a higher priority than others. If the finding already has a
     * counter, we want to include it in the list so that another finding merged to that finding doesn't
     * also get a counter, leading to that vulnerability getting double counted. Also, if one is marked
     * "firstFindingForVuln" we probably want that one.
     */
    @Override
    public Collection<Integer> getEarliestFindingIdsForVulnPerChannel(List<Integer> appIds) {

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(Finding.class)
                .createAlias("vulnerability", "vulnAlias")
                .createAlias("vulnAlias.application", "appAlias")
                .createAlias("scan", "scanAlias")
                .createAlias("scanAlias.applicationChannel", "appChannelAlias")
                .addOrder(Order.asc("scanAlias.importTime"))
                .add(eq("appAlias.active", true))
                .setProjection(Projections.projectionList()
                        .add(property("scanAlias.importTime")) // 0
                        .add(property("appChannelAlias.id"))   // 1
                        .add(property("vulnAlias.id"))         // 2
                        .add(property("id"))                   // 3
                        .add(property("firstFindingForVuln"))  // 4
                        .add(property("hasStatisticsCounter")) // 5
                );

        if (appIds != null && !appIds.isEmpty()) {
            criteria.add(in("appAlias.id", appIds));
        }

        List<Object[]> results = criteria.list();

        // map makes more sense than array because the ints aren't small
        // this is the hashed (time + app channel + vuln ID) -> finding ID
        Map<Integer, Integer> resultMap = map();

        for (Object[] singleResult : results) {
            // this boolean means that the vulnerability should be counted instead of
            // other vulnerabilities with the same hash. The singleResult[5] section
            // indicates that the finding has already been counted and helps us to not double-count
            // vulnerabilities.
            boolean highPriority = true;
            if (singleResult[4] != null && singleResult[5] != null) {
                highPriority = (Boolean) singleResult[4] || (Boolean) singleResult[5];
            }
            int hash = hashIt(singleResult[0], singleResult[1], singleResult[2]);

            if (highPriority || !resultMap.containsKey(hash)) {
                // add the entry for the finding ID
                resultMap.put(hash, (Integer) singleResult[3]);
            }
        }

        return resultMap.values();
    }

	@Override
	public List<Integer> mapIDsThatNeedCountersInApps(List<Integer> appIds, Collection<Integer> findingIdRestrictions) {

		// get list of finding IDs to ScanRepeatFindingMapIDs
		ProjectionList list = Projections.projectionList()
				.add(Projections.id()) // 0
				.add(Projections.property("findingAlias.id")); // 1
		List<Object[]> idArrayList = getBasicMapCriteria()
				.createAlias("finding", "findingAlias")
				.setProjection(list)
				.list();

		// move results into Java Map
		// needs to be int -> list<int> because you can have multiple maps to a single finding ID
		// and they all need counters
		Map<Integer, List<Integer>> findingIdToMapIdMap = map();
		for (Object[] integers : idArrayList) {
			if (integers[0] instanceof Integer && integers[1] instanceof Integer) {
				Integer findingId = (Integer) integers[1], mapId = (Integer) integers[0];
				if (!findingIdToMapIdMap.containsKey(findingId)) {
					findingIdToMapIdMap.put(findingId, listOf(Integer.class));
				}

				findingIdToMapIdMap.get(findingId).add(mapId);
			}
		}

		// keep only valid finding IDs
		Set<Integer> keys = findingIdToMapIdMap.keySet();
		keys.retainAll(findingIdRestrictions);

		// map to the ScanRepeatFindingMap IDs
		List<Integer> mapIds = list();
		for (Integer key : keys) {
			mapIds.addAll(findingIdToMapIdMap.get(key));
		}
		return mapIds;
	}

    private Criteria getBasicMapCriteria() {

		DetachedCriteria detachedCriteria = DetachedCriteria.forClass(StatisticsCounter.class)
				.createAlias("scanRepeatFindingMap", "mapAlias")
				.add(Restrictions.isNotNull("scanRepeatFindingMap"))
				.setProjection(property("mapAlias.id"));

		return sessionFactory.getCurrentSession()
				.createCriteria(ScanRepeatFindingMap.class)
				.add(Property.forName("id").notIn(detachedCriteria));
	}

	public List<ScanRepeatFindingMap> getMapsForIDs(List<Integer> mapIDs) {
		return sessionFactory.getCurrentSession()
				.createCriteria(ScanRepeatFindingMap.class)
				.add(Restrictions.in("id", mapIDs))
				.list();
	}
}
