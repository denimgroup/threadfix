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
package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.map.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.newMap;

@Controller
@RequestMapping("/reports")
@PreAuthorize("hasRole('ROLE_CAN_GENERATE_REPORTS')")
public class ReportsD3Controller {
	
	private final SanitizedLogger log = new SanitizedLogger(ReportsD3Controller.class);
    private static final ObjectWriter WRITER = ControllerUtils.getObjectWriter(AllViews.RestViewScanStatistic.class);

    @Autowired
	private ReportsService reportsService;
    @Autowired
    private TagService tagService;

	@RequestMapping(value="/trendingScans", method = RequestMethod.POST)
	public @ResponseBody String processTrendingScans(@ModelAttribute ReportParameters reportParameters,
                                                                               HttpServletRequest request) throws IOException {
        log.info("Generating trending scans report");
        String responseString = WRITER.writeValueAsString(
                RestResponse.success(reportsService.generateTrendingReport(reportParameters, request)));
        return responseString;
		
	}

    @RequestMapping(value="/scansComparison", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Map<String, Object>> processScanComparison(@ModelAttribute ReportParameters reportParameters,
                                                                         HttpServletRequest request) throws IOException {
        log.info("Generating scans comparison report");
        return null;

    }

    @RequestMapping(value="/snapshot", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Map<String, Object>> processSnapShot(@ModelAttribute ReportParameters reportParameters,
                                                                                 HttpServletRequest request) throws IOException {
        log.info("Generating snapshot report");
        Map<String, Object> map = reportsService.generateSnapshotReport(reportParameters,
                request);
        map.put("tags", tagService.loadAll());
        return RestResponse.success(map);

    }

}