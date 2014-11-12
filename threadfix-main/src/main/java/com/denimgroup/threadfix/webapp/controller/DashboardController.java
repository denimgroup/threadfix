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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import org.codehaus.jackson.map.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {
	
	public DashboardController(){}

    @Autowired
    private DefaultConfigService defaultConfigService;
    @Autowired
	private VulnerabilityCommentService vulnerabilityCommentService;
    @Autowired
	private ScanService scanService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
	private OrganizationService organizationService;
    @Autowired
    private FilterJsonBlobService filterJsonBlobService;

	private final SanitizedLogger log = new SanitizedLogger(DashboardController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		
		model.addAttribute("recentComments", vulnerabilityCommentService.loadMostRecentFiltered(5));
		model.addAttribute("recentScans", scanService.loadMostRecentFiltered(5));

        List<Organization> organizationList = organizationService.loadAllActiveFilter();

		model.addAttribute("teams", organizationService.loadAllActiveFilter());
        PermissionUtils.addPermissions(model, null, null, Permission.CAN_GENERATE_REPORTS);

        if (defaultConfigService.isReportCacheDirty()) {
            for (Organization organization : organizationList) {
                for (Application app : organization.getActiveApplications()) {
                    vulnerabilityService.updateVulnerabilityReport(app);
                }
            }
            DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();
            config.setHasCachedData(true);
            defaultConfigService.saveConfiguration(config);
        }

		return "dashboard/dashboard";
	}

    @RequestMapping(value="/leftReport", method=RequestMethod.GET)
    public @ResponseBody String leftReport(HttpServletRequest request) {

        ReportParameters parameters = getParameters(request, ReportFormat.TRENDING);
        Map<String, Object> map = reportsService.generateTrendingReport(parameters, request);
        map.put("savedFilters", filterJsonBlobService.loadAll());

        return ControllerUtils.writeSuccessObjectWithView(map, AllViews.RestViewScanStatistic.class);
    }


	@RequestMapping(value="/rightReport", method=RequestMethod.GET)
	public @ResponseBody RestResponse<List<Map<String, Object>>> rightReport(HttpServletRequest request) {
		if (request.getParameter("appId") != null) {
			return RestResponse.success(report(request, ReportFormat.TOP_TEN_VULNS).getReportList());
		} else {
			return RestResponse.success(report(request, ReportFormat.TOP_TEN_APPS).getReportList());
		}
	}

    public ReportCheckResultBean report(HttpServletRequest request, ReportFormat reportFormat) {
        ReportParameters parameters = getParameters(request, reportFormat);
        ReportCheckResultBean resultBean = reportsService.generateDashboardReport(parameters, request);

        return resultBean;
    }

    private ReportParameters getParameters(HttpServletRequest request, ReportFormat reportFormat) {
        int orgId = -1, appId = -1;
        if (request.getParameter("orgId") != null) {
            orgId = safeParseInt(request.getParameter("orgId"));
        }
        if (request.getParameter("appId") != null) {
            appId = safeParseInt(request.getParameter("appId"));
        }
        ReportParameters parameters = new ReportParameters();
        parameters.setApplicationId(appId);
        parameters.setOrganizationId(orgId);
        parameters.setFormatId(1);
        parameters.setReportFormat(reportFormat);

        return parameters;
    }
	
	public int safeParseInt(String string) {
		if (string.matches("^[0-9]+$")) {
			try {
				return Integer.valueOf(string);
			} catch (NumberFormatException e) {
				log.warn("Non-numeric string was passed to DashboardController", e); // should never happen
			}
		} else {
			log.warn("Non-numeric string was passed to DashboardController: " + string);
		}
        assert false : "Non-integer values indicate a coding error: " + string;
		return -1;
	}

}
