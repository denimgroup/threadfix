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

import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.dao.StatisticsCounterDao;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScanRepeatFindingMap;
import com.denimgroup.threadfix.data.entities.StatisticsCounter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
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

    @Override
    public void updateStatistics(List<Scan> scans) {
        checkStatisticsCounters();

        runQueries(scans);
    }

    private void checkStatisticsCounters() {

        addMissingFindingCounters();
        addMissingMapCounters();
    }

    private void addMissingMapCounters() {
        Long total = scanDao.totalMapsThatNeedCounters();

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
    }

    private void addMissingFindingCounters() {
        Long total = scanDao.totalFindingsThatNeedCounters();

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
    }

    private void runQueries(List<Scan> scans) {

        long start = System.currentTimeMillis();

        List<Map<String, Object>> totalMap = statisticsCounterDao.getFindingSeverityMap();

        Map<Integer, Long[]> scanStatsMap = map();

        for (Map<String, Object> stringLongMap : totalMap) {

            Integer scanId = (Integer) stringLongMap.get("scanId"),
                    severity = (Integer) stringLongMap.get("genericSeverityId");
            Long total = (Long) stringLongMap.get("total");

            if (!scanStatsMap.containsKey(scanId)) {
                scanStatsMap.put(scanId, new Long[]{ 0L, 0L, 0L, 0L, 0L });
            }

            scanStatsMap.get(scanId)[severity - 1] = total;
        }

        for (Scan scan : scans) {
            if (scanStatsMap.containsKey(scan.getId())) {
                Long[] stats = scanStatsMap.get(scan.getId());
                scan.setNumberCriticalVulnerabilities(stats[4]);
                scan.setNumberHighVulnerabilities(stats[3]);
                scan.setNumberMediumVulnerabilities(stats[2]);
                scan.setNumberLowVulnerabilities(stats[1]);
                scan.setNumberInfoVulnerabilities(stats[0]);
                scanDao.saveOrUpdate(scan);
                System.out.print(")");
            } else {
                System.out.print("(");
            }
        }

        System.out.println("Critical/High/Medium/Low/Info calculated in " + (System.currentTimeMillis() - start) + " ms.");

    }

}
