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

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.dao.EmptyScanDao;
import com.denimgroup.threadfix.data.dao.ScanDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.interop.ChannelImporter;
import com.denimgroup.threadfix.importer.interop.ChannelImporterFactory;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.queue.QueueSender;
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

        List<String> originalFileNames = scan.getOriginalFileNames();
        String finalName = null;

        if (originalFileNames != null && !originalFileNames.isEmpty()) {
            finalName = originalFileNames.get(0);
        } else {
            finalName = scan.getFileName();
        }

        response.setHeader("Content-Disposition", "attachment; filename=\"" + finalName + "\"");
        response.setHeader("Content-Transfer-Encoding", "binary");
        response.setContentLength((int)scanFile.length());
        response.setContentType("application/xml");

        try {
            InputStream in = new FileInputStream(scanFile);
            ServletOutputStream out = response.getOutputStream();
            byte[] outputByteBuffer = new byte[65535];

            int remainingSize = in.read(outputByteBuffer, 0, 65535);

            // copy binary content to output stream
            while (remainingSize != -1) {
                out.write(outputByteBuffer, 0, remainingSize);
                remainingSize = in.read(outputByteBuffer, 0, 65535);
            }
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

    @Override
    public int deleteScanFileLocations() {

        List<String> scanFilenames = scanDao.loadScanFilenames();
        DefaultConfiguration defaultConfig = defaultConfigService.loadCurrentConfiguration();
        String fileUploadLocation = defaultConfig.getFileUploadLocation();

        for (String scanFilename : scanFilenames) {

            if (defaultConfig.fileUploadLocationExists()) {
                File directory = new File(fileUploadLocation);

                if (directory.exists()) {
                    File fileUploaded = new File(fileUploadLocation + File.separator + scanFilename);
                    deleteFile(fileUploaded.getPath());
                } else {
                    throw new RestIOException("Directory at path:  " + fileUploadLocation + " does not exist.", -1);
                }
            }
        }

        return scanDao.deleteScanFileLocations();
    }

    private void deleteFile(String fileName) {
        File file = new File(fileName);
        if (file.exists() && !file.delete()) {
            LOG.warn("Something went wrong trying to delete: " + fileName);
            file.deleteOnExit();
        }
    }
}