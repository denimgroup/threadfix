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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.util.Result;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static com.denimgroup.threadfix.remote.response.RestResponse.*;

@RestController
@RequestMapping("/rest/scans")
public class ScansRestController extends TFRestController {

    @Autowired
    private ScanService scanService;

    @RequestMapping(headers="Accept=application/json", value="/{scanId}", method= RequestMethod.GET)
    @JsonView(AllViews.RestViewScan2_1.class)
    public Object getScanDetails(HttpServletRequest request,
                                 @PathVariable("scanId") int scanId) throws IOException {

        LOG.info("Received REST request for details of scan " + scanId + ".");

        Scan scan = scanService.loadScan(scanId);

        int appId = -1;

        if (scan != null && scan.getApplication() != null && scan.getApplication().getId() != null) {
            appId = scan.getApplication().getId();
        }

        Result<String> keyCheck = checkKey(request, RestMethod.SCAN_DETAILS, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        if (scan != null) {
            return success(scan);
        } else {
            return failure("No scan exists for requested id");
        }
    }
}
