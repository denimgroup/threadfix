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
package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.dao.ApplicationDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.net.URL;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 2/6/15.
 */
@Component
public class RemappingTestHarness {

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

    public static Application getApplicationWith(String... paths) {
        return SpringConfiguration.getSpringBean(RemappingTestHarness.class)
                .getApplicationWithInternal(RemappingTests.FROM_ID, RemappingTests.TO_ID, paths);
    }

    @Transactional(readOnly = true)
    public Application getApplicationWithInternal(String unmappedType, String cweId, String... paths) {
        List<String> finalPaths = list();

        for (String path : paths) {
            URL resource = RemappingTests.class.getClassLoader().getResource("merging/" + path);

            assert resource != null : "Failed to find resource for " + path;
            String file = resource.getFile();

            finalPaths.add(file);
        }

        Application application = merger.mergeSeriesInternal(null, finalPaths);

        ChannelType channelType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getDbName());

        ChannelVulnerability channelVulnerability = channelVulnerabilityDao.retrieveByName(channelType, unmappedType);

        assert channelVulnerability != null : "Unable to find channel vuln for " + unmappedType;

        // this *should* find the same hibernate-managed object if we're in the same Spring container
        channelVulnerabilityService.createMapping(ScannerType.SSVL.getDbName(), channelVulnerability.getId(), cweId);

        applicationDao.saveOrUpdate(application);

        return application;
    }
}