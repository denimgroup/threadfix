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

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.util.Calendar;
import java.util.List;
import java.util.Set;

// TODO figure out this Transactional stuff
// TODO make another service to hold the scan history controller stuff
@Service
@Transactional(readOnly = false)
public class ScanServiceImpl implements ScanService {

    private static final SanitizedLogger LOG = new SanitizedLogger(ScanServiceImpl.class);

    @Autowired
    private ScanDao                scanDao                = null;
    @Autowired
    private ApplicationChannelDao  applicationChannelDao  = null;
    @Autowired
    private EmptyScanDao           emptyScanDao           = null;
    @Autowired
    private QueueSender            queueSender            = null;
    @Autowired(required = false)
    @Nullable
    private PermissionService      permissionService      = null;
    @Autowired
    private ChannelImporterFactory channelImporterFactory = null;
    @Autowired
    private DefaultConfigService defaultConfigService;

    @Override
    public List<Scan> loadAll() {
        return scanDao.retrieveAll();
    }

    @Override
    public Scan loadScan(Integer scanId) {
        return scanDao.retrieveById(scanId);
    }

    @Override
    @Transactional(readOnly = false)
    public void storeScan(Scan scan) {
        scanDao.saveOrUpdate(scan);
    }

    @Override
    public String downloadScan(Scan scan, String fullFilePath, HttpServletResponse response) {

        File scanFile = new File(fullFilePath);

        response.addHeader("Content-Disposition", "attachment; filename=\""+scan.getFileName()+"\"");
        response.setContentLength((int)scanFile.length());
        response.setContentType("application/octet-stream");

        try {
            InputStream in = new FileInputStream(scanFile);
            ServletOutputStream out = response.getOutputStream();
            IOUtils.copy(in, out);
            in.close();
            out.flush();
            out.close();

        } catch (FileNotFoundException e) {
            return "File was not found at " + fullFilePath;

        } catch (IOException e) {
            return "There was an error reading the uploaded scan file.";
        }

        return null;

    }

    @Override
    @Transactional(readOnly = false)
    public void addFileToQueue(@Nonnull Integer channelId, @Nonnull String fileName, @Nonnull Calendar scanDate) {

        if (!ApplicationChannel.matchesFileHandleFormat(fileName)) {
            String message = "Bad file name (" + fileName + ") passed into addFileToQueue. Exiting.";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        }

        ApplicationChannel applicationChannel = applicationChannelDao
                .retrieveById(channelId);

        Integer appId = applicationChannel.getApplication().getId();
        Integer orgId = applicationChannel.getApplication()
                .getOrganization().getId();

        queueSender.addScanToQueue(fileName, channelId, orgId, appId, scanDate, applicationChannel);
    }

    @Override
    @Nonnull
    public ScanCheckResultBean checkFile(Integer channelId, String fileName) {
        if (channelId == null || fileName == null) {
            LOG.warn("Scan file checking failed because there was null input.");
            return new ScanCheckResultBean(ScanImportStatus.NULL_INPUT_ERROR);
        }

        if (!ApplicationChannel.matchesFileHandleFormat(fileName)) {
            String message = "Bad file name (" + fileName + ") passed into addFileToQueue. Exiting.";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        }

        ApplicationChannel channel = applicationChannelDao.retrieveById(channelId);

        if (channel == null) {
            LOG.warn("The ApplicationChannel could not be loaded.");
            return new ScanCheckResultBean(ScanImportStatus.OTHER_ERROR);
        }

        ChannelImporter importer = channelImporterFactory.getChannelImporter(channel);

        if (importer == null) {
            LOG.warn("No importer could be loaded for the ApplicationChannel.");
            return new ScanCheckResultBean(ScanImportStatus.OTHER_ERROR);
        }

        importer.setFileName(fileName);

        ScanCheckResultBean result = importer.checkFile();

        if (!result.getScanCheckResult().equals(ScanImportStatus.SUCCESSFUL_SCAN)) {
            importer.deleteScanFile();
        }

        Calendar scanQueueDate = applicationChannelDao.getMostRecentQueueScanTime(channel.getId());

        if (scanQueueDate != null && result.getTestDate() != null &&
                !result.getTestDate().after(scanQueueDate)) {
            LOG.warn(ScanImportStatus.MORE_RECENT_SCAN_ON_QUEUE.toString());
            return new ScanCheckResultBean(ScanImportStatus.MORE_RECENT_SCAN_ON_QUEUE, result.getTestDate());
        }

        return result;
    }

    @Override
    public Integer saveEmptyScanAndGetId(Integer channelId, String fileName) {

        if (fileName == null) {
            LOG.warn("Saving the empty file failed. Check filesystem permissions.");
            return null;
        } else if (!ApplicationChannel.matchesFileHandleFormat(fileName)) {
            String message = "Bad file name (" + fileName + ") passed into addFileToQueue. Exiting.";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        } else {
            EmptyScan emptyScan = new EmptyScan();
            emptyScan.setApplicationChannel(applicationChannelDao.retrieveById(channelId));
            emptyScan.setAlreadyProcessed(false);
            emptyScan.setDateUploaded(Calendar.getInstance());
            emptyScan.setFileName(fileName);
            emptyScanDao.saveOrUpdate(emptyScan);
            return emptyScan.getId();
        }
    }

    @Override
    public void addEmptyScanToQueue(Integer emptyScanId) {
        EmptyScan emptyScan = emptyScanDao.retrieveById(emptyScanId);

        if (emptyScan.getAlreadyProcessed() ||
                emptyScan.getApplicationChannel() == null ||
                emptyScan.getApplicationChannel().getId() == null ||
                emptyScan.getApplicationChannel().getApplication() == null ||
                emptyScan.getApplicationChannel().getApplication().getId() == null ||
                emptyScan.getApplicationChannel().getApplication().getOrganization() == null ||
                emptyScan.getApplicationChannel().getApplication().getOrganization().getId() == null ||
                emptyScan.getFileName() == null) {
            LOG.warn("The empty scan was not added to the queue. It was either already processed or incorrectly configured.");
            return;
        }

        ApplicationChannel applicationChannel = emptyScan.getApplicationChannel();

        Integer appId = applicationChannel.getApplication().getId();
        Integer orgId = applicationChannel.getApplication()
                .getOrganization().getId();

        String fileName = emptyScan.getFileName();

        queueSender.addScanToQueue(fileName, applicationChannel.getId(), orgId, appId, null, applicationChannel);

        emptyScan.setAlreadyProcessed(true);
        emptyScanDao.saveOrUpdate(emptyScan);
    }

    @Override
    public void deleteEmptyScan(Integer emptyScanId) {
        EmptyScan emptyScan = emptyScanDao.retrieveById(emptyScanId);

        if (emptyScan != null) {
            emptyScan.setAlreadyProcessed(true);
            File file = DiskUtils.getScratchFile(emptyScan.getFileName());
            if (file.exists()) {
                if (!file.delete())
                    file.deleteOnExit();
            }

            emptyScanDao.saveOrUpdate(emptyScan);
        }
    }

    @Override
    public long getFindingCount(Integer scanId) {
        return scanDao.getFindingCount(scanId);
    }

    @Override
    public long getUnmappedFindingCount(Integer scanId) {
        return scanDao.getFindingCountUnmapped(scanId);
    }

    // TODO bounds checking
    @Override
    public void loadStatistics(Scan scan) {
        if (scan == null || scan.getId() == null) {
            return;
        }
        scan.setNumWithoutGenericMappings((int) scanDao.getNumberWithoutGenericMappings(scan.getId()));
        scan.setTotalNumberSkippedResults((int) scanDao.getTotalNumberSkippedResults(scan.getId()));
        scan.setNumWithoutChannelVulns((int) scanDao.getNumberWithoutChannelVulns(scan.getId()));
        scan.setTotalNumberFindingsMergedInScan((int) scanDao.getTotalNumberFindingsMergedInScan(scan.getId()));
    }

    @Override
    public List<Scan> loadMostRecentFiltered(int number) {

        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return scanDao.retrieveMostRecent(number);
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return scanDao.retrieveMostRecent(number, appIds, teamIds);
        } else {
            return scanDao.retrieveMostRecent(number, null, null);
        }
    }

    @Override
    public int getScanCount() {
        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return scanDao.getScanCount();
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return scanDao.getScanCount(appIds, teamIds);
        } else {
            return scanDao.getScanCount(null, null);
        }
    }

    @Override
    public List<Scan> getTableScans(Integer page) {
        if (permissionService != null) {
            if (permissionService.isAuthorized(Permission.READ_ACCESS, null, null)) {
                return scanDao.getTableScans(page);
            }

            Set<Integer> appIds = permissionService.getAuthenticatedAppIds();
            Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

            return scanDao.getTableScans(page, appIds, teamIds);
        } else {
            return scanDao.getTableScans(page, null, null);
        }
    }

}