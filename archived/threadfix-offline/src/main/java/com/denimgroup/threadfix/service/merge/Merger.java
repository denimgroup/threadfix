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

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.util.ScanParser;
import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.*;

/**
 * This class's primary use is for non-web-context ThreadFix merging.
 *
 * Created by mac on 7/28/14.
 */
@Component
public class Merger extends SpringBeanAutowiringSupport {

    @Autowired
    private ScanParser scanParser;
    @Autowired
    private ScanMerger     scanMerger;
    @Autowired
    private ApplicationDao applicationDao;
    @Autowired
    private OrganizationDao organizationDao;
    @Autowired
    private ChannelTypeDao channelTypeDao;
    @Autowired
    private ApplicationChannelDao applicationChannelDao;
    @Autowired
    private ScanDao scanDao;

    /**
     * This is public because @Transactional doesn't work for private methods. Don't call it yourself.
     * @param scannerName scanner name of ALL the scan files.
     * @param filePaths one file path for each scan
     * @return an application with a list of scans from the given files
     */
    public Application getApplicationInternal(Application application, ScannerType scannerName, String[] filePaths) {
        assert scanMerger != null : "No Merger found, fix your Spring context.";
        assert scanParser != null : "No Parser found, fix your Spring context.";

        List<Scan> scans = list();

        ApplicationChannel channel = new ApplicationChannel();
        ChannelType channelType = channelTypeDao.retrieveByName(scannerName.getDisplayName());

        assert channelType != null : "Unable to find ChannelType for name " + scannerName.getDisplayName();

        channel.setChannelType(channelType);
        channel.setApplication(application);
        channel.setScanList(scans);
        application.setScans(scans);
        application.setVulnerabilities(listOf(Vulnerability.class));
        application.setChannelList(list(channel));
        application.setName("application merge.");

        applicationDao.saveOrUpdate(application);

        for (String file : filePaths) {
            Scan resultScan = scanParser.getScan(file);
            scanMerger.merge(resultScan, channel, false);
            application.getScans().add(resultScan);
        }

        return application;
    }

    @Transactional(readOnly = true)
    public List<Scan> getScanListInternal(Application application, ScannerType scannerName, String[] filePaths) {
        Application resultingApplication = getApplicationInternal(application, scannerName, filePaths);

        return resultingApplication.getScans();
    }

    public static List<Scan> getScanListFromPaths(Application application, ScannerType scannerName, String... filePaths) {
        return SpringConfiguration.getSpringBean(Merger.class).getScanListInternal(application, scannerName, filePaths);
    }

    public static List<Scan> getScanListFromPaths(ScannerType scannerName, String... filePaths) {
        return SpringConfiguration.getSpringBean(Merger.class).getScanListInternal(new Application(), scannerName, filePaths);
    }

    public static Application mergeFromDifferentScanners(String sourceRoot,  String... filePaths) {
        return mergeFromDifferentScanners(sourceRoot, Arrays.asList(filePaths));
    }

    public static Application mergeFromDifferentScanners(String sourceRoot, Collection<String> filePaths) {
        return SpringConfiguration.getSpringBean(Merger.class).mergeFromDifferentScannersInternal(sourceRoot, filePaths);
    }

    @Transactional(readOnly = true)
    public Application mergeFromDifferentScannersInternal(String sourceRoot, Collection<String> filePaths) {
        assert scanMerger != null : "No Merger found, fix your Spring context.";
        assert scanParser != null : "No Parser found, fix your Spring context.";

        Application application = new Application();
        application.setVulnerabilities(listOf(Vulnerability.class));
        application.setChannelList(new ArrayList<ApplicationChannel>());
        application.setRepositoryFolder(sourceRoot);
        application.setName("MergeApplication");
        application.setScans(new ArrayList<Scan>());

        applicationDao.saveOrUpdate(application);

        for (String file : filePaths) {
            Scan resultScan = scanParser.getScan(file);
            resultScan.getApplicationChannel().setApplication(application);

            String channelName = resultScan.getApplicationChannel().getChannelType().getName();
            ChannelType hibernateChannelType = channelTypeDao.retrieveByName(channelName);
            resultScan.getApplicationChannel().setChannelType(hibernateChannelType);

            application.getChannelList().add(resultScan.getApplicationChannel());
            scanMerger.merge(resultScan, resultScan.getApplicationChannel(), false);
            application.getScans().add(resultScan);
        }

        return application;
    }

    public Application mergeSeries(String sourceRoot, Collection<String> filePaths) {
        return SpringConfiguration.getSpringBean(Merger.class).mergeSeriesInternal(sourceRoot, filePaths);
    }

    @Transactional(readOnly = true)
    public Application mergeSeriesInternal(String sourceRoot, Collection<String> filePaths) {
        assert scanMerger != null : "No Merger found, fix your Spring context.";
        assert scanParser != null : "No Parser found, fix your Spring context.";

        Application application = new Application();
        application.setVulnerabilities(listOf(Vulnerability.class));
        application.setChannelList(new ArrayList<ApplicationChannel>());
        application.setRepositoryFolder(sourceRoot);
        application.setName("MergeApplication");
        application.setScans(new ArrayList<Scan>());
        application.setOrganization(new Organization());
        application.getOrganization().setName("TEST NAME");
        application.getOrganization().setActive(true);

        organizationDao.saveOrUpdate(application.getOrganization());
        applicationDao.saveOrUpdate(application);

        Map<String, ApplicationChannel> channelMap = map();

        for (String file : filePaths) {
            Scan resultScan = scanParser.getScan(file);
            String channelName = resultScan.getApplicationChannel().getChannelType().getName();

            ApplicationChannel channel = channelMap.get(channelName);

            if (channel == null) {
                channel = resultScan.getApplicationChannel();
                channel.setChannelType(channelTypeDao.retrieveByName(channelName));
                channel.setApplication(application);
                channel.setScanList(listOf(Scan.class));
                channelMap.put(channelName, channel);
            }

            application.getChannelList().add(channel);
            applicationChannelDao.saveOrUpdate(channel);

            scanMerger.merge(resultScan, channel);
            application.getScans().add(resultScan);
            scanDao.saveOrUpdate(resultScan);

            channel.getScanList().add(resultScan);
        }

        return application;
    }

}
