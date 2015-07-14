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

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;

@Controller
@RequestMapping("/reports")
@PreAuthorize("hasRole('ROLE_CAN_GENERATE_REPORTS')")
public class ReportsController {
	
	private final SanitizedLogger log = new SanitizedLogger(ReportsController.class);

    @Autowired
	private OrganizationService organizationService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
	private VulnerabilityService vulnerabilityService;
    @Autowired
    private TagService tagService;
	@Autowired
	private ReportService reportService;
	@Autowired
	private CacheBustService cacheBustService;

	@ModelAttribute("organizationList")
	public List<Organization> getOrganizations() {
		List<Organization> organizationList = organizationService.loadAllActiveFilter();
		List<Organization> returnList = list();

		for (Organization org : organizationList) {
			List<Application> validApps = PermissionUtils.filterApps(org);
			if (validApps != null && !validApps.isEmpty()) {
				org.setActiveApplications(validApps);
				returnList.add(org);
			}
		}
		return returnList;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		model.addAttribute("hasVulnerabilities", vulnerabilityService.activeVulnerabilitiesExist());
		model.addAttribute("reportParameters", new ReportParameters());
		model.addAttribute("error", ControllerUtils.getErrorMessage(request));
		model.addAttribute("firstReport", ControllerUtils.getItem(request, "reportId"));
		model.addAttribute("firstTeamId", ControllerUtils.getItem(request, "teamId"));
		model.addAttribute("firstAppId", ControllerUtils.getItem(request, "appId"));
        boolean isEnterprise = EnterpriseTest.isEnterprise();
        model.addAttribute("isEnterprise", isEnterprise);
        PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_TAGS);

		// Return custom report entities
		List<Report> reports = reportService.loadAllNonNativeReportsByLocationType(ReportLocation.ANALYTIC);
		if (reports != null && reports.size() > 0) {
			model.addAttribute("reportJsPaths", cacheBustService.notCachedJsPaths(request, reports));
			model.addAttribute("customReports", reports);
		}

		return "reports/index";
	}

	@RequestMapping(value="/{reportId}", method = RequestMethod.GET)
	public String toReport(@PathVariable("reportId") int reportId, HttpServletRequest request) {
		ControllerUtils.addItem(request, "reportId", reportId);
		return "redirect:/reports";
	}
	
	@RequestMapping(value="/{reportId}/{teamId}", method = RequestMethod.GET)
	public String toReport(@PathVariable("reportId") int reportId,
			@PathVariable("teamId") int teamId, HttpServletRequest request) {
		ControllerUtils.addItem(request, "reportId", reportId);
		ControllerUtils.addItem(request, "teamId", teamId);
		return "redirect:/reports";
	}
	
	@RequestMapping(value="/{reportId}/{teamId}/{appId}", method = RequestMethod.GET)
	public String toReport(@PathVariable("reportId") int reportId,
			@PathVariable("teamId") int teamId,
			@PathVariable("appId") int appId,
			HttpServletRequest request) {
		ControllerUtils.addItem(request, "reportId", reportId);
		ControllerUtils.addItem(request, "teamId", teamId);
		ControllerUtils.addItem(request, "appId", appId);
		return "redirect:/reports";
	}

    @RequestMapping(value="/trendingScans", method = RequestMethod.POST)
	@JsonView(AllViews.RestViewScanStatistic.class)
    public @ResponseBody Object processTrendingScans(@ModelAttribute ReportParameters reportParameters,
                                                     HttpServletRequest request) throws IOException {
        log.info("Generating trending scans report");
        return RestResponse.success(reportsService.generateTrendingReport(reportParameters, request));
    }

    @RequestMapping(value="/snapshot", method = RequestMethod.POST)
	@JsonView(AllViews.VulnSearchApplications.class)
    public @ResponseBody RestResponse<Map<String, Object>> processSnapShot(@ModelAttribute ReportParameters reportParameters,
                                                                           HttpServletRequest request) throws IOException {
        log.info("Generating snapshot report");
        Map<String, Object> map = reportsService.generateSnapshotReport(reportParameters,
                request);
        map.put("tags", tagService.loadAllApplicationTags());
		map.put("vulnTags", tagService.loadAllVulnTags());
        return RestResponse.success(map);
    }

    @RequestMapping(value="/getTopApps", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Map<String, Object>> processTopApps(@ModelAttribute VulnerabilitySearchParameters reportParameters,
                                                                           HttpServletRequest request) throws IOException {
        log.info("Generating Top 20 Vulnerable applications report");
        Map<String, Object> map = reportsService.generateMostAppsReport(reportParameters,
                request);
        return RestResponse.success(map);
    }

}