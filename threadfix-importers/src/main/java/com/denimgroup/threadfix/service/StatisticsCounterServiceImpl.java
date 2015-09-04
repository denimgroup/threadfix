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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.data.entities.StatisticsCounter.getStatisticsCounter;

/**
 * Created by mcollins on 5/13/15.
 */
@Service
public class StatisticsCounterServiceImpl implements StatisticsCounterService {

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
        addMissingFindingCounters();
        addMissingMapCounters();
    }

    private void addMissingMapCounters() {
        Long total = scanDao.totalMapsThatNeedCounters();

        long start = System.currentTimeMillis();

        System.out.println("Total: " + total);

        int current = total.intValue() / 100;

        while (current >= 0) {

            System.out.print(".");

            List<ScanRepeatFindingMap> mapsThatNeedCounters = scanDao.getMapsThatNeedCounters(current);

            for (ScanRepeatFindingMap map : mapsThatNeedCounters) {
                if (!map.getFinding().isFirstFindingForVuln()) {
                    continue;
                }

                StatisticsCounter statisticsCounter = getStatisticsCounter(map);
                if (statisticsCounter != null) {
                    System.out.print("-");
                    statisticsCounterDao.saveOrUpdate(statisticsCounter);
                }
            }
            current --;
        }

        System.out.println("Took " + (System.currentTimeMillis() - start) + " ms to add missing map counters.");
    }

    private void addMissingFindingCounters() {
        Long total = scanDao.totalFindingsThatNeedCounters();

        long start = System.currentTimeMillis();

        System.out.println("Total: " + total);

        int current = total.intValue() / 100;

        while (current >= 0) {

            System.out.print(".");

            List<Finding> findingsThatNeedCounters = scanDao.getFindingsThatNeedCounters(current);

            for (Finding finding : findingsThatNeedCounters) {
                if (!finding.isFirstFindingForVuln()) {
                    continue;
                }

                StatisticsCounter statisticsCounter = getStatisticsCounter(finding);
                if (statisticsCounter != null) {
                    System.out.print(",");
                    statisticsCounterDao.saveOrUpdate(statisticsCounter);
                }
                finding.setHasStatisticsCounter(true);
                findingDao.saveOrUpdate(finding);
            }
            current --;
        }

        System.out.println("Took " + (System.currentTimeMillis() - start) + " ms to add missing finding counters.");
    }

    private void runQueries(List<Scan> scans) {

        long start = System.currentTimeMillis();

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

        System.out.println("Critical/High/Medium/Low/Info calculated in " + (System.currentTimeMillis() - start) + " ms.");

    }

    private Set<Integer> getAppsWithTheirOwnFilters() {
        Set<Integer> appsWithTheirOwnFilters = set();
        List<SeverityFilter> severityFilters = severityFilterService.loadAllFilters();
        List<VulnerabilityFilter> vulnerabilityFilters = vulnerabilityFilterDao.retrieveAll();

        List<MultiLevelFilter> filters = list();
        filters.addAll(severityFilters);
        filters.addAll(vulnerabilityFilters);

        for (MultiLevelFilter filter : filters) {
            if (filter.getOrganization() != null) {
                for (Application application : filter.getOrganization().getApplications()) {
                    appsWithTheirOwnFilters.add(application.getId());
                }
            } else if (filter.getApplication() != null) {
                appsWithTheirOwnFilters.add(filter.getApplication().getId());
            }
        }
        return appsWithTheirOwnFilters;
    }

    private void processScans(int orgID, int appID, List<Scan> scans) {

        Map<Integer, Long[]> scanStatsMap = getIntegerMap(orgID, appID, scans);

        List<Integer> ignoredVulnerabilityIds = getVulnerabilityIdsToIgnore(orgID, appID);

        Map<Integer, Long> closedMap   = getClosedMap(ignoredVulnerabilityIds);
        Map<Integer, Long> reopenedMap = getReopenedMap(ignoredVulnerabilityIds);
        applyStatistics(scans, scanStatsMap, closedMap, reopenedMap);
    }

    private void applyStatistics(List<Scan> scans, Map<Integer, Long[]> scanStatsMap, Map<Integer, Long> closedMap, Map<Integer, Long> reopenedMap) {

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
                System.out.print(")");
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
                System.out.print("(");
            }
        }
    }

    private Map<Integer, Long> getClosedMap(List<Integer> ignoredVulnerabilityIds) {
        List<Map<String, Object>> rawMap = vulnerabilityFilterDao.getScanClosedVulnerabilitiesMap(ignoredVulnerabilityIds);

        return condenseMap(rawMap);
    }

    private Map<Integer, Long> getReopenedMap(List<Integer> ignoredVulnerabilityIds) {
        List<Map<String, Object>> rawMap = vulnerabilityFilterDao.getScanReopenedVulnerabilitiesMap(ignoredVulnerabilityIds);

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

    private List<Integer> getVulnerabilityIdsToIgnore(int orgID, int appID) {
        List<Integer> filteredSeverities = getFilteredSeverities(orgID, appID),
                filteredVulnerabilities = getFilteredVulnerabilities(orgID, appID);

        return vulnerabilityFilterDao.getIgnoredIds(filteredSeverities, filteredVulnerabilities);
    }

    private Map<Integer, Long> getTotalsMap() {
        List<Map<String, Object>> rawTotals =
                statisticsCounterDao.getRawFindingTotalMap();

        return condenseMap(rawTotals);
    }

    private Map<Integer, Long[]> getIntegerMap(int orgID, int appID, List<Scan> scans) {
        List<Integer> filteredSeverities = getFilteredSeverities(orgID, appID),
                filteredVulnerabilities = getFilteredVulnerabilities(orgID, appID);
        List<Integer> filteredChannelSeverities;

        Map<Integer, Integer> genericSeverityIdToSeverityMap = generateGenericSeverityMap();

        List<Map<String, Object>> totalMap = list();
        for (Scan scan: scans) {
            filteredChannelSeverities = scanResultFilterDao.retrieveAllChannelSeveritiesByChannelType(scan.getApplicationChannel().getChannelType());
            totalMap.addAll(statisticsCounterDao.getFindingSeverityMap(
                            filteredSeverities,
                            filteredVulnerabilities,
                            filteredChannelSeverities, scan));
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

        if (severityFilter == null) {
            return list();
        }

        if (!severityFilter.getShowInfo()) {
            severityIds.add(1);
        }
        if (!severityFilter.getShowLow()) {
            severityIds.add(2);
        }
        if (!severityFilter.getShowMedium()) {
            severityIds.add(3);
        }
        if (!severityFilter.getShowHigh()) {
            severityIds.add(4);
        }
        if (!severityFilter.getShowCritical()) {
            severityIds.add(5);
        }

        return severityIds;
    }

    private List<Integer> getFilteredVulnerabilities(int orgID, int appID) {
        List<VulnerabilityFilter> vulnerabilityFilters = vulnerabilityFilterDao.retrieveAllEffective(orgID, appID);

        List<Integer> filteredIds = list();

        for (VulnerabilityFilter vulnerabilityFilter : vulnerabilityFilters) {
            filteredIds.add(vulnerabilityFilter.getId());
        }

        return filteredIds;
    }

}
