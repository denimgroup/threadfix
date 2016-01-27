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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.UploadScanService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;

/**
 * Created by mac on 9/11/14.
 */
@RestController
public class UploadScanController {

    private static final SanitizedLogger LOG = new SanitizedLogger(UploadScanController.class);

    @Autowired
    private UploadScanService uploadScanService;

    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/upload/remote", method = RequestMethod.POST, produces = "text/plain")
    @JsonView(AllViews.TableRow.class)
    public String uploadScan2(@PathVariable("appId") int appId,
                             @PathVariable("orgId") int orgId,
                             HttpServletRequest request,
                             MultipartRequest multiPartRequest) throws IOException {
        Object o = uploadScan(appId, orgId, request, multiPartRequest);

        ObjectWriter mapper = new CustomJacksonObjectMapper().writerWithView(AllViews.TableRow.class);

        return mapper.writeValueAsString(o);
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
                             MultipartRequest multiPartRequest) throws IOException {

        LOG.info("Received REST request to upload a scan to application " + appId + ".");

        if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
            return failure("You don't have permission to upload scans.");
        }

        return uploadScanService.processMultiFileUpload(multiPartRequest.getFileMap().values(),
                orgId, appId, request.getParameter("channelId"), false);
    }

    /**
     * Allows the user to upload bulk scans to an existing application.
     *
     */
    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/upload/remote/bulk", method = RequestMethod.POST, produces = "application/json")
    @JsonView(AllViews.TableRow.class)
    public Object bulkUploadScans(@PathVariable("appId") int appId,
                             @PathVariable("orgId") int orgId,
                             HttpServletRequest request,
                             MultipartRequest multiPartRequest) throws IOException {

        LOG.info("Received REST request to upload multiple scan to application " + appId + ".");

        if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
            return failure("You don't have permission to upload scans.");
        }

        return uploadScanService.processMultiFileUpload(multiPartRequest.getFileMap().values(),
                orgId, appId, request.getParameter("channelId"), true);
    }
}
