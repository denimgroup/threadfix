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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * Created by mac on 9/11/14.
 */
@RestController
public class UploadScanController {

    private static final SanitizedLogger LOG = new SanitizedLogger(UploadScanController.class);

    @Autowired
    private ScanTypeCalculationService scanTypeCalculationService;
    @Autowired
    private ScanService                scanService;
    @Autowired
    private ScanMergeService           scanMergeService;
    @Autowired
    private OrganizationService        organizationService;

    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/upload/remote", method = RequestMethod.POST, produces = "text/plain")
    @JsonView(AllViews.TableRow.class)
    public String uploadScan2(@PathVariable("appId") int appId,
                             @PathVariable("orgId") int orgId,
                             HttpServletRequest request,
                             @RequestParam("file") MultipartFile file) throws IOException {
        Object o = uploadScan(appId, orgId, request, file);

        ObjectWriter mapper = new CustomJacksonObjectMapper().writerWithView(AllViews.TableRow.class);
        String s = mapper.writeValueAsString(o);

        return s;
    }

    /**
     * Allows the user to upload a scan to an existing application.
     *
     * @return Team with updated stats.
     */
    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/upload/remote", method = RequestMethod.POST, produces = "application/json")
    @JsonView(AllViews.TableRow.class)
    public Object uploadScan(@PathVariable("appId") int appId,
                             @PathVariable("orgId") int orgId,
                             HttpServletRequest request,
                             @RequestParam("file") MultipartFile file) throws IOException {

        LOG.info("Received REST request to upload a scan to application " + appId + ".");

        if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
            return failure("You don't have permission to upload scans.");
        }

        Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));

        if (myChannelId == null) {
            return failure("Failed to determine the scan type.");
        }

        String fileName = scanTypeCalculationService.saveFile(myChannelId, file);

        try {
            ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);

            if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
                Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);

                if (scan != null) {
                    Organization organization = organizationService.loadById(orgId);
                    return success(organization);
                } else {
                    return failure("Something went wrong while processing the scan.");
                }
            } else {
                return failure(returnValue.getScanCheckResult().toString());
            }
        } finally { // error recovery code
            File diskFile = DiskUtils.getScratchFile(fileName);

            if (diskFile.exists()) {
                LOG.info("After scan upload, file is still present. Attempting to delete.");
                boolean deletedSuccessfully = diskFile.delete();

                if (deletedSuccessfully) {
                    LOG.info("Successfully deleted scan file.");
                } else {
                    LOG.error("Unable to delete file.");
                }
            }
        }
    }
}
