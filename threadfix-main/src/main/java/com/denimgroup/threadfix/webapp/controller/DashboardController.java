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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.util.DateUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

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
    @Autowired
    private GenericSeverityService genericSeverityService;
    @Autowired
    private CacheBustService cacheBustService;
    @Autowired(required = false)
    private LicenseService licenseService;

	private final SanitizedLogger log = new SanitizedLogger(DashboardController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();
        List<Organization> organizationList = organizationService.loadAllActiveFilter();

        PermissionUtils.addPermissions(model, null, null, Permission.CAN_GENERATE_REPORTS);
		model.addAttribute("recentComments", vulnerabilityCommentService.loadMostRecentFiltered(5));
		model.addAttribute("recentScans", scanService.loadMostRecentFiltered(5));
		model.addAttribute("teams", organizationList);
        model.addAttribute("config", config);
        model.addAttribute("reportJsPaths", cacheBustService.notCachedJsPaths(request, config.getDashboardReports()));

        if (licenseService != null && PermissionUtils.isAuthorized(Permission.CAN_MANAGE_SYSTEM_SETTINGS)) {
            model.addAttribute("expirationNotification",
                    DateUtils.getDaysBetween(Calendar.getInstance(), licenseService.getExpirationDate()));
        }

        if (defaultConfigService.isReportCacheDirty()) {
            for (Organization organization : organizationList) {
                for (Application app : organization.getActiveApplications()) {
                    vulnerabilityService.updateVulnerabilityReport(app);
                }
            }
            config.setHasCachedData(true);
            defaultConfigService.saveConfiguration(config);
        }

		return "dashboard/dashboard";
	}

    @JsonView(AllViews.RestViewScanStatistic.class)
    @RequestMapping(value="/leftReport", method=RequestMethod.GET)
    public @ResponseBody Object leftReport(HttpServletRequest request) throws JsonProcessingException {
        long start = System.currentTimeMillis();
        log.info("Processing left report");

        ReportParameters parameters = getParameters(request, ReportFormat.TRENDING);
        Map<String, Object> map = reportsService.generateTrendingReport(parameters, request);
        map.put("savedFilters", filterJsonBlobService.loadAll());
        map.put("genericSeverities", genericSeverityService.loadAll());

        log.info("Left report took " + (System.currentTimeMillis() - start) + " ms");

        return RestResponse.success(map);
    }


	@RequestMapping(value="/rightReport", method=RequestMethod.GET)
	public @ResponseBody RestResponse rightReport(HttpServletRequest request) {

        long start = System.currentTimeMillis();
        log.info("Processing right report");
        ReportFormat reportFormat = (request.getParameter("appId") != null) ? ReportFormat.TOP_TEN_VULNS : ReportFormat.TOP_TEN_APPS;

        ReportParameters parameters = getParameters(request, reportFormat);
        ReportCheckResultBean resultBean = reportsService.generateDashboardReport(parameters, request);

        log.info("Right report took " + (System.currentTimeMillis() - start) + " ms");

        return RestResponse.success(map(
                "map", resultBean.getReportList(),
                "genericSeverities", genericSeverityService.loadAll())
        );
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
