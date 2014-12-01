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

import com.denimgroup.threadfix.annotations.MappingsUpdater;
import com.denimgroup.threadfix.data.dao.DefaultConfigurationDao;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.importer.loader.AnnotationLoader;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor;
import org.springframework.context.ApplicationContext;
import org.springframework.core.OrderComparator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Calendar;
import java.util.Collections;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional(readOnly = false) // used to be true
class ScannerMappingsUpdaterServiceImpl implements ScannerMappingsUpdaterService {

    @Autowired
    private DefaultConfigurationDao defaultConfigurationDao;

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

    @Override
    public void updateMappings() {
        updateMappings(null);
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
    public void updateMappings(ApplicationContext applicationContext) {
        log.info("Start updating Scanner mapping from startup");

        DefaultConfiguration config = loadCurrentConfiguration();
        Calendar pluginTimestamp = config.getLastScannerMappingsUpdate();

        UpdaterHarness harness = new UpdaterHarness(pluginTimestamp);

        Calendar latest = null;

        for (Updater updater : getUpdaters(applicationContext)) {
            Calendar mostRecentDate = harness.executeUpdates(updater);
            if (latest == null || latest.before(mostRecentDate)) {
                latest = mostRecentDate;
            }
        }

        config.setLastScannerMappingsUpdate(latest);

        defaultConfigurationDao.saveOrUpdate(config);

        log.info("Ended updating Scanner mapping from startup");
    }

    @Override
    public ScanPluginCheckBean checkPluginJar(ApplicationContext applicationContext) {
        DefaultConfiguration configuration = loadCurrentConfiguration();

        if (configuration != null && configuration.getLastScannerMappingsUpdate() != null) {

            Calendar databaseDate = configuration.getLastScannerMappingsUpdate();
            Calendar pluginDate = getMostRecentFileDate(databaseDate, applicationContext);

            if (pluginDate != null && !pluginDate.after(databaseDate)) {
                return new ScanPluginCheckBean(false, databaseDate, pluginDate);
            } else {
                return new ScanPluginCheckBean(true, databaseDate, pluginDate);
            }
        } else  {
            return new ScanPluginCheckBean(true, null, null);
        }
    }

    @Override
    public ScanPluginCheckBean checkPluginJar() {
        return checkPluginJar(null);
    }

    private Calendar getMostRecentFileDate(Calendar baseDate, ApplicationContext applicationContext) {
        UpdaterHarness harness = new UpdaterHarness(baseDate);

        Calendar latest = null;

        for (Updater updater : getUpdaters(applicationContext)) {
            Calendar mostRecentDate = harness.findMostRecentDate(updater);
            if (latest == null || latest.before(mostRecentDate)) {
                latest = mostRecentDate;
            }
        }

        return latest;
    }

    List<Updater> updaters = null;

    private List<Updater> getUpdaters(ApplicationContext applicationContext) {
        if (updaters == null) {
            updaters = AnnotationLoader.getListOfConcreteClass(
                    MappingsUpdater.class,
                    "com.denimgroup.threadfix.importer.update.impl",
                    Updater.class);

            if (applicationContext != null) {
                AutowiredAnnotationBeanPostProcessor bpp = new AutowiredAnnotationBeanPostProcessor();
                bpp.setBeanFactory(applicationContext.getAutowireCapableBeanFactory());

                for (Updater updater : updaters) {
                    bpp.processInjection(updater);
                }
            } else {
                assert false : "ApplicationContext was null, unable to autowire.";
            }
        }

        Collections.sort(updaters, OrderComparator.INSTANCE);

        return updaters;
    }

}
