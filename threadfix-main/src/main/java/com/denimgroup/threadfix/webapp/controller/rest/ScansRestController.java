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
