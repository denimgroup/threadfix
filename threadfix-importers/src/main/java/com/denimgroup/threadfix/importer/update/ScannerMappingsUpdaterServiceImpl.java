////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer.update;

import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.importer.util.DateUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.importer.util.DateUtils.getLatestCalendar;

@Service
@Transactional(readOnly = false) // used to be true
class ScannerMappingsUpdaterServiceImpl implements ScannerMappingsUpdaterService {

    @Autowired
    private DefaultConfigurationDao     defaultConfigurationDao;
    @Autowired
    private GenericMappingsUpdater      genericMappingsUpdater;
    @Autowired
    private ChannelVulnerabilityUpdater channelVulnerabilityUpdater;
    @Autowired
    private DefectTrackerUpdater        defectTrackerUpdater;
    @Autowired
    private ActivityFeedUpdater         eventModelUpdater;
    @Autowired
    WafsUpdater wafsUpdater;

    private final SanitizedLogger log = new SanitizedLogger(ScannerMappingsUpdaterServiceImpl.class);

    @Override
    public List<String> getSupportedScanners() {
        List<String> scanners = list();

        ScannerType[] importers = ScannerType.values();

        if (importers != null) {
            for (ScannerType importer : importers) {
                scanners.add(importer.getFullName());
            }
        }

        Collections.sort(scanners);

        return scanners;
    }

    public DefaultConfiguration loadCurrentConfiguration() {
        DefaultConfiguration configuration;

        List<DefaultConfiguration> list = defaultConfigurationDao.retrieveAll();
        if (list.size() == 0) {
            configuration = DefaultConfiguration.getInitialConfig();
        } else if (list.size() > 1) {
            DefaultConfiguration config = list.get(0);
            list.remove(0);
            for (DefaultConfiguration defaultConfig : list) {
                defaultConfigurationDao.delete(defaultConfig);
            }
            configuration = config;
        } else {
            configuration = list.get(0);
        }

        assert configuration != null;
        return configuration;
    }

    @Override
    @Transactional
    public void updateMappings() {
        log.info("Start updating Scanner mapping from startup");

        DefaultConfiguration config = loadCurrentConfiguration();
        Calendar pluginTimestamp = config.getLastScannerMappingsUpdate();

        UpdaterHarness harness = new UpdaterHarness(pluginTimestamp);

        Calendar genericMappingsTime = harness.executeUpdates(genericMappingsUpdater);
        Calendar channelMappingsTime = harness.executeUpdates(channelVulnerabilityUpdater);
        Calendar defectTrackerTime = harness.executeUpdates(defectTrackerUpdater);
        Calendar wafTime = harness.executeUpdates(wafsUpdater);
        Calendar eventModelTime = harness.executeUpdates(eventModelUpdater);

        Calendar latestCalendar = getLatestCalendar(
                pluginTimestamp, genericMappingsTime, channelMappingsTime, defectTrackerTime, wafTime, eventModelTime);
        config.setLastScannerMappingsUpdate(latestCalendar);

        defaultConfigurationDao.saveOrUpdate(config);

        log.info("Ended updating Scanner mapping from startup");
    }

    @Override
    public ScanPluginCheckBean checkPluginJar() {
        DefaultConfiguration configuration = loadCurrentConfiguration();

        if (configuration != null && configuration.getLastScannerMappingsUpdate() != null) {

            Calendar databaseDate = configuration.getLastScannerMappingsUpdate();
            Calendar pluginDate = getMostRecentFileDate(databaseDate);

            if (pluginDate != null && databaseDate != null && !pluginDate.after(databaseDate)) {
                return new ScanPluginCheckBean(false, databaseDate, pluginDate);
            } else {
                return new ScanPluginCheckBean(true, databaseDate, pluginDate);
            }
        } else  {
            return new ScanPluginCheckBean(true, null, null);
        }
    }

    private Calendar getMostRecentFileDate(Calendar baseDate) {
        UpdaterHarness harness = new UpdaterHarness(baseDate);

        Calendar genericMappingsTime = harness.findMostRecentDate(genericMappingsUpdater);
        Calendar channelMappingsTime = harness.findMostRecentDate(channelVulnerabilityUpdater);
        Calendar defectTrackerTime = harness.findMostRecentDate(defectTrackerUpdater);
        Calendar wafsTime = harness.findMostRecentDate(wafsUpdater);
        Calendar eventModelType = harness.findMostRecentDate(eventModelUpdater);

        return DateUtils.getLatestCalendar(
                genericMappingsTime, channelMappingsTime, defectTrackerTime, wafsTime, eventModelType);
    }

}
