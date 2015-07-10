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
import com.denimgroup.threadfix.data.entities.SeverityFilter;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.SeverityFilterService;
import com.denimgroup.threadfix.service.StatisticsCounterService;
import com.denimgroup.threadfix.service.merge.Merger;
import com.denimgroup.threadfix.service.merge.RemappingTests;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.net.URL;
import java.util.List;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.setFrom;

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

    public static Application getApplicationWith(List<Integer> severities, String... paths) {
        return SpringConfiguration.getSpringBean(StatisticsCounterTests.class)
                .getApplicationWithInternal(RemappingTests.FROM_ID, RemappingTests.TO_ID, severities,  paths);
    }

    @Transactional(readOnly = true)
    public Application getApplicationWithInternal(String unmappedType, String cweId, List<Integer> severities, String... paths) {
        List<String> finalPaths = list();

        for (String path : paths) {
            URL resource = RemappingTests.class.getClassLoader().getResource("merging/" + path);

            assert resource != null : "Failed to find resource for " + path;
            String file = resource.getFile();

            finalPaths.add(file);
        }

        Application application = merger.mergeSeriesInternal(null, finalPaths);

        // this *should* find the same hibernate-managed object if we're in the same Spring container
//        channelVulnerabilityService.createMapping(ScannerType.SSVL.getDbName(), unmappedType, cweId);

        applicationDao.saveOrUpdate(application);

        setSeverityFilters(severities);

        statisticsCounterService.updateStatistics(application.getScans());

        return application;
    }

    private void setSeverityFilters(List<Integer> severities) {

        SeverityFilter filter = new SeverityFilter();

        Set<Integer> severitySet = setFrom(severities);

        filter.setShowCritical(severitySet.contains(5));
        filter.setShowHigh(severitySet.contains(4));
        filter.setShowMedium(severitySet.contains(3));
        filter.setShowLow(severitySet.contains(2));
        filter.setShowInfo(severitySet.contains(1));

        severityFilterService.save(filter, -1, -1);
    }

    @Test
    public void testAllOn() {

    }


}
