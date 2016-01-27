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

package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.Collection;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Service
@Transactional
public class UploadScanServiceImpl implements UploadScanService{

    private final SanitizedLogger log = new SanitizedLogger(UploadScanServiceImpl.class);

    @Autowired
    private ScanTypeCalculationService scanTypeCalculationService;
    @Autowired
    private ScanService scanService;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private ScanMergeService scanMergeService;
    @Autowired
    private DefaultConfigService defaultConfigService;
    @Autowired(required = false)
    private PolicyStatusService policyStatusService;

    @Override
    public Object processMultiFileUpload(
            Collection<MultipartFile> files,
            Integer orgId,
            Integer appId,
            String channelIdString,
            boolean isBulkScans) {

        if (files.isEmpty()) {
            return failure("No files selected.");
        }

        if (appId == null) {
            return failure("No appId");
        }

        Integer channelId = null;
        List<Integer> channelIds = list();
        List<String> fileNames = list(), originalNames = list();
        try {

            for (MultipartFile file : files) {
                Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, channelIdString);

                if (myChannelId == null) {
                    return failure("Failed to determine the scan type.");
                }

                if (channelId != null && !channelId.equals(myChannelId) && !isBulkScans) {
                    return failure("Scans are not of the same type.");
                }

                channelId = myChannelId;
                channelIds.add(myChannelId);

                String fileName = scanTypeCalculationService.saveFile(channelId, file);

                fileNames.add(fileName);
                originalNames.add(file.getOriginalFilename());

                ScanCheckResultBean returnValue = scanService.checkFile(channelId, fileName);

                if (!ScanImportStatus.SUCCESSFUL_SCAN.equals(returnValue.getScanCheckResult())) {
                    return failure(returnValue.getScanCheckResult().toString());
                }
            }

            List<Scan> resultScans = list();
            Scan scan = null;
            if (isBulkScans) {
                resultScans = scanMergeService.saveRemoteScansAndRun(channelIds, fileNames, originalNames);
            } else {
                scan = scanMergeService.saveRemoteScanAndRun(channelId, fileNames, originalNames);
            }

            if (scan != null || resultScans.size() > 0) {
                if (orgId != null) {
                    Organization organization = organizationService.loadById(orgId);
                    return success(organization);
                } else {
                    return success(isBulkScans ? resultScans : scan);
                }
            } else {
                return failure("Something went wrong while processing the scan.");
            }
        } finally {

            // only delete if the user hasn't set a directory
            if (!defaultConfigService.loadCurrentConfiguration().fileUploadLocationExists()) {
                if (!fileNames.isEmpty()) {
                    for (String fileName : fileNames) {
                        File diskFile = DiskUtils.getScratchFile(fileName);

                        if (diskFile.exists()) {
                            log.info("After scan upload, file is still present. Attempting to delete.");
                            boolean deletedSuccessfully = diskFile.delete();

                            if (deletedSuccessfully) {
                                log.info("Successfully deleted scan file.");
                            } else {
                                log.error("Unable to delete file.");
                            }
                        }
                    }
                }
            }

            if (policyStatusService != null) {
                policyStatusService.runStatusCheck(appId);
            }
        }
    }
}
