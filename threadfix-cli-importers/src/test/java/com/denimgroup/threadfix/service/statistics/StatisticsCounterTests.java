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
package com.denimgroup.threadfix.service.statistics;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.StatisticsCounterService;
import com.denimgroup.threadfix.service.merge.Merger;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import sun.jvm.hotspot.utilities.Assert;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.service.merge.RemappingTestHarness.getFilePaths;

/**
 * Created by mcollins on 6/11/15.
 */
@Component
public class StatisticsCounterTests {

    @Autowired
    Merger merger;
    @Autowired
    ChannelVulnerabilityService channelVulnerabilityService;
    @Autowired
    ChannelVulnerabilityDao channelVulnerabilityDao;
    @Autowired
    ChannelTypeDao channelTypeDao;
    @Autowired
    ApplicationDao applicationDao;
    @Autowired
    StatisticsCounterService statisticsCounterService;
    @Autowired
    SeverityFilterService severityFilterService;

    public static Application getApplicationWith(String... paths) {
        return SpringConfiguration.getSpringBean(StatisticsCounterTests.class)
                .getApplicationWithInternal(paths);
    }

    @Transactional(readOnly = true)
    public Application getApplicationWithInternal(String... paths) {
        List<String> finalPaths = getFilePaths("statistics/", paths);

        Application application = merger.mergeSeriesInternal(null, finalPaths);

        // this *should* find the same hibernate-managed object if we're in the same Spring container
//        channelVulnerabilityService.createMapping(ScannerType.SSVL.getDbName(), unmappedType, cweId);

        applicationDao.saveOrUpdate(application);

        statisticsCounterService.checkStatisticsCountersInApps(list(application.getId()));
        statisticsCounterService.updateStatistics(application.getScans());

        return application;
    }

    /**
     * This is to test that merged vulnerabilities are counted properly in scans
     */
    @Test
    public void testMergeStatistics() {
        Application application = getApplicationWith("testfire-arachni.xml", "testfire-zap.xml");

        List<Scan> scans = application.getScans();

        Assert.that(scans.size() == 2, "Had " + scans.size() + " scans instead of " + 2);

        for (Scan scan : scans) {
            Integer total = scan.getNumberTotalVulnerabilities();
            Assert.that(total == 32 || total == 69, "Had " + total + " vulnerabilities, not 32 or 69.");
        }
    }

    @Test
    public void testBaseStatistics() {
        Application application = getApplicationWith("testfire-arachni.xml");

        List<Scan> scans = application.getScans();

        Assert.that(scans.size() == 1, "Had " + scans.size() + " scans instead of " + 1);

        for (Scan scan : scans) {
            Integer total = scan.getNumberTotalVulnerabilities();
            Assert.that(total == 32, "Had " + total + " vulnerabilities, not 32.");
        }
    }
}
