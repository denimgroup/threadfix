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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.interfaces.MultiLevelFilter;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.data.entities.StatisticsCounter.getStatisticsCounter;
import static java.lang.System.currentTimeMillis;

/**
 * Created by mcollins on 5/13/15.
 */
@Service
public class StatisticsCounterServiceImpl implements StatisticsCounterService {

    private static final SanitizedLogger LOG = new SanitizedLogger(StatisticsCounterServiceImpl.class);

    @Autowired
    ScanDao scanDao;
    @Autowired
    StatisticsCounterDao statisticsCounterDao;
    @Autowired
    FindingDao findingDao;
    @Autowired
    SeverityFilterService severityFilterService;
    @Autowired
    VulnerabilityFilterDao vulnerabilityFilterDao;
    @Autowired
    GenericSeverityDao genericSeverityDao;
    @Autowired
    ScanResultFilterDao scanResultFilterDao;

    @Override
    public void updateStatistics(List<Scan> scans) {
        runQueries(scans);
    }

    @Override
    public void checkStatisticsCounters() {

        // these are the candidate finding IDs based on whether or not they should count for the vuln
        Collection<Integer> findingIdRestrictions =
                scanDao.getEarliestFindingIdsForVulnPerChannel(null);
        addMissingFindingCounters(null, findingIdRestrictions);
        addMissingMapCounters(null, findingIdRestrictions);
    }

    @Override
    public void checkStatisticsCountersInApps(List<Integer> appIds) {

        // these are the candidate finding IDs based on whether or not they should count for the vuln
        Collection<Integer> findingIdRestrictions =
                scanDao.getEarliestFindingIdsForVulnPerChannel(null);

        addMissingFindingCounters(appIds, findingIdRestrictions);
        addMissingMapCounters(appIds, findingIdRestrictions);
    }

    @Override
    public void updateFindingCounter(Finding finding, Integer oldVulnId) {
        if (finding.getHasStatisticsCounter()
                || finding.getVulnerability() == null
                || finding.getVulnerability().getId() == null
                || statisticsCounterDao.retrieveByVulnId(finding.getVulnerability().getId()).size() == 0) {
            //Delete old counter
            statisticsCounterDao.deleteByVulnId(oldVulnId);
            statisticsCounterDao.deleteByFindingId(finding.getId());

            StatisticsCounter statisticsCounter = getStatisticsCounter(finding);
            if (statisticsCounter != null) {
                statisticsCounterDao.saveOrUpdate(statisticsCounter);
            }
            finding.setHasStatisticsCounter(true);
            findingDao.saveOrUpdate(finding);
        }

    }

    private void addMissingMapCounters(List<Integer> appIds, Collection<Integer> findingIdRestrictions) {
        if (appIds != null && appIds.size() == 0) {
            LOG.debug("There were no missing map counters to add.");
            return;
        }

        long start = currentTimeMillis();

        List<Integer> idList = scanDao.mapIDsThatNeedCountersInApps(appIds, findingIdRestrictions);

        LOG.info("Total maps missing counters: " + idList.size());

        int total = idList.size();
        int current = total / 100;

        while (current >= 0) {

            LOG.debug("Processing at index " + current + " out of " + total);

            // we'll paginate by 100 for now
            int pageStart = current * 100, pageEnd = pageStart + 100;
            if (pageStart < 0) pageStart = 0;
            if (pageEnd > total) {
                pageEnd = total;
            }
            List<Integer> ids = idList.subList(pageStart, pageEnd);

            if (ids.isEmpty()) {
                break;
            }

            LOG.debug("Processing " + current + " out of " + idList.size() + ".");

            List<ScanRepeatFindingMap> mapsThatNeedCounters = scanDao.getMapsForIDs(ids);

            for (ScanRepeatFindingMap map : mapsThatNeedCounters) {
                if (!map.getFinding().getHasStatisticsCounter()) {
                    continue;
                }

                StatisticsCounter statisticsCounter = getStatisticsCounter(map);
                if (statisticsCounter != null) {
                    statisticsCounterDao.saveOrUpdate(statisticsCounter);
                }
            }
            current --;
        }

        LOG.info("Took " + (currentTimeMillis() - start) + " ms to add missing map counters.");
    }

    private void addMissingFindingCounters(List<Integer> appIds, Collection<Integer> findingIdRestrictions) {
        if (appIds != null && appIds.size() == 0) {
            LOG.debug("There were no missing finding counters to add.");
            return;
        }

        List<Integer> findingIds = scanDao.findingIdsThatNeedCountersInApps(appIds, findingIdRestrictions);

        int total = findingIds.size();
        long start = currentTimeMillis();

        LOG.debug("Total findings that need counters: " + total);

        int current = total / 100;

        while (current >= 0) {

            LOG.debug("Processing at index " + current + " out of " + total);

            int pageStart = current * 100, pageEnd = pageStart + 100;

            if (pageStart < 0) pageStart = 0;

            if (pageEnd > total) {
                pageEnd = total;
            }
            List<Integer> targetFindingIds = findingIds.subList(pageStart, pageEnd);

            List<Finding> findingsThatNeedCounters =
                    scanDao.getFindingsWithIds(targetFindingIds);

            for (Finding finding : findingsThatNeedCounters) {

                StatisticsCounter statisticsCounter = getStatisticsCounter(finding);
                if (statisticsCounter != null) {
                    statisticsCounterDao.saveOrUpdate(statisticsCounter);
                }
                finding.setHasStatisticsCounter(true);
                findingDao.saveOrUpdate(finding);
            }
            current --;
        }

        LOG.info("Took " + (currentTimeMillis() - start) + " ms to add missing finding counters.");
    }

    private void runQueries(List<Scan> scans) {

        long start = currentTimeMillis();

        // TODO use existing filters when calculating these statistics

        Set<Integer> appsWithTheirOwnFilters = getAppsWithTheirOwnFilters();

        List<Scan> useGlobal = list();
        Map<Application, List<Scan>> appToScanMap = map();

        for (Scan scan : scans) {
            if (scan == null || scan.getApplication() == null) {
                continue;
            }

            if (appsWithTheirOwnFilters.contains(scan.getApplication().getId())) {
                if (!appToScanMap.containsKey(scan.getApplication())) {
                    appToScanMap.put(scan.getApplication(), list(scan));
                } else {
                    appToScanMap.get(scan.getApplication()).add(scan);
                }
            } else {
                useGlobal.add(scan);
            }
        }

        processScans(-1, -1, useGlobal);

        for (Map.Entry<Application, List<Scan>> entry : appToScanMap.entrySet()) {
            processScans(entry.getKey().getOrganization().getId(), entry.getKey().getId(), entry.getValue());
        }

        LOG.debug("Critical/High/Medium/Low/Info calculated in " + (currentTimeMillis() - start) + " ms.");

    }

    private Set<Integer> getAppsWithTheirOwnFilters() {
        Set<Integer> appsWithTheirOwnFilters = set();
        List<SeverityFilter> severityFilters = severityFilterService.loadAllFilters();
        List<VulnerabilityFilter> vulnerabilityFilters = vulnerabilityFilterDao.retrieveAll();

        List<MultiLevelFilter> filters = list();
        filters.addAll(severityFilters);
        filters.addAll(vulnerabilityFilters);

        for (MultiLevelFilter filter : filters) {
            if (!(filter instanceof SeverityFilter) || ((SeverityFilter) filter).getEnabled()) {
                if (filter.getOrganization() != null) {
                    for (Application application : filter.getOrganization().getApplications()) {
                        appsWithTheirOwnFilters.add(application.getId());
                    }
                } else if (filter.getApplication() != null) {
                    appsWithTheirOwnFilters.add(filter.getApplication().getId());
                }
            }
        }
        return appsWithTheirOwnFilters;
    }

    private void processScans(int orgID, int appID, List<Scan> scans) {

        Map<Integer, Long[]> scanStatsMap = getIntegerMap(orgID, appID, scans);

        List<Integer> filteredSeverities = getFilteredSeverities(orgID, appID),
                filteredVulnerabilities = getFilteredVulnerabilities(orgID, appID);

        Map<Integer, Long> closedMap   = getClosedMap(filteredSeverities, filteredVulnerabilities);
        Map<Integer, Long> reopenedMap = getReopenedMap(filteredSeverities, filteredVulnerabilities);
        applyStatistics(scans, scanStatsMap, closedMap, reopenedMap);
    }

    private void applyStatistics(List<Scan> scans, Map<Integer, Long[]> scanStatsMap,
                                 Map<Integer, Long> closedMap, Map<Integer, Long> reopenedMap) {

        Map<Integer, Long> totalsMap = getTotalsMap();

        for (Scan scan : scans) {
            if (scanStatsMap.containsKey(scan.getId())) {
                Long[] stats = scanStatsMap.get(scan.getId());
                scan.setNumberCriticalVulnerabilities(stats[4]);
                scan.setNumberHighVulnerabilities(stats[3]);
                scan.setNumberMediumVulnerabilities(stats[2]);
                scan.setNumberLowVulnerabilities(stats[1]);
                scan.setNumberInfoVulnerabilities(stats[0]);
                Long total = stats[0] + stats[1] + stats[2] + stats[3] + stats[4];
                scan.setNumberTotalVulnerabilities(total.intValue());

                Long numberClosed = closedMap.get(scan.getId());
                if (numberClosed != null) {
                    scan.setNumberClosedVulnerabilities(numberClosed.intValue());
                } else {
                    scan.setNumberClosedVulnerabilities(0);
                }

                Long numberReopened = reopenedMap.get(scan.getId());
                if (numberReopened != null) {
                    scan.setNumberResurfacedVulnerabilities(numberReopened.intValue());
                } else {
                    scan.setNumberResurfacedVulnerabilities(0);
                }

                Long originalTotal = totalsMap.get(scan.getId());
                if (originalTotal != null) {
                    scan.setNumberHiddenVulnerabilities(originalTotal.intValue() - total.intValue());
                } else {
                    scan.setNumberHiddenVulnerabilities(0);
                }

                scanDao.saveOrUpdate(scan);
                LOG.debug("Successfully processed scan with ID " + scan.getId());
            } else {
                scan.setNumberCriticalVulnerabilities(0L);
                scan.setNumberHighVulnerabilities(0L);
                scan.setNumberMediumVulnerabilities(0L);
                scan.setNumberLowVulnerabilities(0L);
                scan.setNumberInfoVulnerabilities(0L);
                scan.setNumberTotalVulnerabilities(0);

                Long numberClosed = closedMap.get(scan.getId());
                if (numberClosed != null) {
                    scan.setNumberClosedVulnerabilities(numberClosed.intValue());
                } else {
                    scan.setNumberClosedVulnerabilities(0);
                }

                Long numberReopened = reopenedMap.get(scan.getId());
                if (numberReopened != null) {
                    scan.setNumberResurfacedVulnerabilities(numberReopened.intValue());
                } else {
                    scan.setNumberResurfacedVulnerabilities(0);
                }

                Long originalTotal = totalsMap.get(scan.getId());
                if (originalTotal != null) {
                    scan.setNumberHiddenVulnerabilities(originalTotal.intValue());
                } else {
                    scan.setNumberHiddenVulnerabilities(0);
                }

                scanDao.saveOrUpdate(scan);
                LOG.debug("Unsuccessfully processed scan with ID " + scan.getId());
            }
        }
    }

    private Map<Integer, Long> getClosedMap(List<Integer> filteredSeverities, List<Integer> filteredVulnerabilities) {
        List<Map<String, Object>> rawMap =
                vulnerabilityFilterDao.getScanClosedVulnerabilitiesMap(filteredSeverities, filteredVulnerabilities);

        return condenseMap(rawMap);
    }

    private Map<Integer, Long> getReopenedMap(List<Integer> filteredSeverities, List<Integer> filteredVulnerabilities) {
        List<Map<String, Object>> rawMap =
                vulnerabilityFilterDao.getScanReopenedVulnerabilitiesMap(filteredSeverities, filteredVulnerabilities);

        return condenseMap(rawMap);
    }

    private Map<Integer, Long> condenseMap(List<Map<String, Object>> rawMap) {
        Map<Integer, Long> returnMap = map();

        for (Map<String, Object> innerMap : rawMap) {
            Integer scanId = (Integer) innerMap.get("scanId");
            Long    count  = (Long) innerMap.get("total");

            returnMap.put(scanId, count);
        }

        return returnMap;
    }

    private Map<Integer, Long> getTotalsMap() {
        List<Map<String, Object>> rawTotals =
                statisticsCounterDao.getRawFindingTotalMap();

        return condenseMap(rawTotals);
    }

    private Map<Integer, Long[]> getIntegerMap(int orgID, int appID, List<Scan> scans) {
        List<Integer> filteredSeverities = getFilteredSeverities(orgID, appID),
                filteredVulnerabilities = getFilteredVulnerabilities(orgID, appID);

        Map<Integer, Integer> genericSeverityIdToSeverityMap = generateGenericSeverityMap();

        List<Map<String, Object>> totalMap = list();
        for (Scan scan: scans) {

            List<ScanResultFilter> scanResultFilters = scanResultFilterDao.loadAllForChannelType(scan.getApplicationChannel().getChannelType());
            List<String> vulnsToHideSubqueries = list();
            int index = 0;
            Map<String, Object> paramsMap = map();

            for (ScanResultFilter scanResultFilter: scanResultFilters) {
                vulnsToHideSubqueries.add(
                        vulnerabilityFilterDao.getVulnsToHideSubquery(
                                scanResultFilter,
                                scan,
                                scan.getApplication(),
                                index));
                paramsMap.put("applicationId" + index, scan.getApplication().getId());
                paramsMap.put("scanId" + index, scan.getId());
                paramsMap.put("genericSeverityIntValue" + index, scanResultFilter.getGenericSeverity().getIntValue());
                paramsMap.put("channelTypeId" + index, scanResultFilter.getChannelType().getId());
                index++;
            }

            totalMap.addAll(statisticsCounterDao.getFindingSeverityMap(
                    filteredSeverities,
                    filteredVulnerabilities,
                    paramsMap,
                    vulnsToHideSubqueries,
                    scan));
        }
        Map<Integer, Long[]> scanStatsMap = map();

        for (Map<String, Object> stringLongMap : totalMap) {

            Integer scanId = (Integer) stringLongMap.get("scanId"),
                    severity = (Integer) stringLongMap.get("genericSeverityId");
            Long total = (Long) stringLongMap.get("total");

            if (!scanStatsMap.containsKey(scanId)) {
                scanStatsMap.put(scanId, new Long[]{ 0L, 0L, 0L, 0L, 0L });
            }

            scanStatsMap.get(scanId)[getSeverityIndex(genericSeverityIdToSeverityMap, severity)] = total;
        }

        return scanStatsMap;
    }

    private int getSeverityIndex(Map<Integer, Integer> genericSeverityIdToSeverityMap, Integer severity) {

        if (genericSeverityIdToSeverityMap.containsKey(severity)) {
            return genericSeverityIdToSeverityMap.get(severity);
        } else {
            throw new IllegalStateException("Got an unrecognized generic severity ID: " + severity);
        }
    }

    private Map<Integer, Integer> generateGenericSeverityMap() {

        List<GenericSeverity> severities = genericSeverityDao.retrieveAll();

        Map<Integer, Integer> returnMap = map();

        for (GenericSeverity severity : severities) {
            returnMap.put(severity.getId(), severity.getIntValue() - 1);
        }

        return returnMap;
    }

    private List<Integer> getFilteredSeverities(int orgID, int appID) {

        List<Integer> severityIds = list();

        SeverityFilter severityFilter = severityFilterService.loadFilter(orgID, appID);

        if (severityFilter == null || !severityFilter.getEnabled()) {
            severityFilter = severityFilterService.getParentFilter(orgID, appID);

            if (severityFilter == null || !severityFilter.getEnabled())
                return list();
        }

        if (!severityFilter.getShowInfo()) {
            GenericSeverity infoSeverity = genericSeverityDao.retrieveByIntValue(1);
            severityIds.add(infoSeverity.getId());
        }
        if (!severityFilter.getShowLow()) {
            GenericSeverity lowSeverity = genericSeverityDao.retrieveByIntValue(2);
            severityIds.add(lowSeverity.getId());
        }
        if (!severityFilter.getShowMedium()) {
            GenericSeverity medSeverity = genericSeverityDao.retrieveByIntValue(3);
            severityIds.add(medSeverity.getId());
        }
        if (!severityFilter.getShowHigh()) {
            GenericSeverity highSeverity = genericSeverityDao.retrieveByIntValue(4);
            severityIds.add(highSeverity.getId());
        }
        if (!severityFilter.getShowCritical()) {
            GenericSeverity criticalSeverity = genericSeverityDao.retrieveByIntValue(5);
            severityIds.add(criticalSeverity.getId());
        }

        return severityIds;
    }

    private List<Integer> getFilteredVulnerabilities(int orgID, int appID) {
        List<VulnerabilityFilter> vulnerabilityFilters = vulnerabilityFilterDao.retrieveAllEffective(orgID, appID);

        List<Integer> filteredIds = list();

        for (VulnerabilityFilter vulnerabilityFilter : vulnerabilityFilters) {
            if (vulnerabilityFilter.getTargetGenericSeverity() == null) {
                filteredIds.add(vulnerabilityFilter.getSourceGenericVulnerability().getId());
            }
        }

        return filteredIds;
    }

}
