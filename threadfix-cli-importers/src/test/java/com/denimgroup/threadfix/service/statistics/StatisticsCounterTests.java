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
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.service.merge.RemappingTestHarness.getFilePaths;
import static org.springframework.test.util.AssertionErrors.assertTrue;

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

        Assert.assertTrue("Had " + scans.size() + " scans instead of 2", scans.size() == 2);

        for (Scan scan : scans) {
            Integer total = scan.getNumberTotalVulnerabilities();
            Assert.assertTrue("Had " + total + " vulnerabilities, not 32 or 69.", total == 32 || total == 69);
        }
    }

    @Test
    public void testBaseStatistics() {
        Application application = getApplicationWith("testfire-arachni.xml");

        List<Scan> scans = application.getScans();

        assertTrue("Had " + scans.size() + " scans instead of 1", scans.size() == 1);

        for (Scan scan : scans) {
            Integer total = scan.getNumberTotalVulnerabilities();
            assertTrue("Had " + total + " vulnerabilities, not 32.", total == 32);
        }
    }

    @Test
    public void testOldVulnerabilitiesCountCorrect() {
        List<Scan> scans = getScans("testfire-zap.xml", "testfire-arachni.xml");
        testTotalAndOld(69, 8, scans);
        testTotalAndOld(32, 0, scans);
    }

    @Test
    public void testOldVulnerabilitiesCountCorrectReverse() {
        List<Scan> scans = getScans("testfire-arachni.xml", "testfire-zap.xml");
        testTotalAndOld(69, 8, scans);
        testTotalAndOld(32, 0, scans);
    }

    @Test
    public void testRepeatStats() {
        List<Scan> scans = getScans("testfire-arachni.xml", "testfire-zap.xml", "testfire-zap2.xml");
        testTotalAndOld(69, 8, scans);
        testTotalAndOld(32, 0, scans);
        testTotalAndOld(69, 69, scans);
    }

    private void testTotalAndOld(int total, int old, List<Scan> scans) {
        for (Scan scan : scans) {
            System.out.println("Checking " + scan.getNumberTotalVulnerabilities() + ", " + scan.getNumberOldVulnerabilities());
            if (scan.getNumberTotalVulnerabilities() == total &&
                    scan.getNumberOldVulnerabilities() == old) {
                return; // we did it!
            }
        }

        assertTrue("Scan with " + total + " vulns didn't have " + old +
                " old vulnerabilities.", false);
    }

    private List<Scan> getScans(String... scanFiles) {
        Application application = getApplicationWith(scanFiles);

        List<Scan> scans = application.getScans();

        assertTrue("Had " + scans.size() + " scans instead of " + scanFiles.length, scans.size() == scanFiles.length);
        return scans;
    }
}
