////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.VulnerabilityCommentService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
	private VulnerabilityCommentService vulnerabilityCommentService;
    @Autowired
	private ScanService scanService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
	private OrganizationService organizationService;

	private final SanitizedLogger log = new SanitizedLogger(DashboardController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request, HttpServletResponse response) {
		
		model.addAttribute("recentComments", vulnerabilityCommentService.loadMostRecentFiltered(5));
		model.addAttribute("recentScans", scanService.loadMostRecentFiltered(5));
		
		model.addAttribute("teams", organizationService.loadAllActiveFilter());

        PermissionUtils.addPermissions(model, null, null, Permission.CAN_GENERATE_REPORTS);

		return "dashboard/dashboard";
	}
	
	@RequestMapping(value="/leftReport", method=RequestMethod.POST)
	public String leftReport(Model model, HttpServletRequest request) {
		model.addAttribute("showEmptyBox", true);
		return report(model, request, ReportFormat.SIX_MONTH_SUMMARY);
	}
	
	@RequestMapping(value="/rightReport", method=RequestMethod.POST)
	public String rightReport(Model model, HttpServletRequest request) {
		model.addAttribute("showEmptyBox", true);
		if (request.getParameter("appId") != null) {
			return report(model, request, ReportFormat.TOP_TEN_VULNS);
		} else {
			return report(model, request, ReportFormat.TOP_TEN_APPS);
		}
	}
	
	public String report(Model model, HttpServletRequest request, ReportFormat reportFormat) {
		
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
		ReportCheckResultBean resultBean = reportsService.generateReport(parameters, request);
		if (resultBean.getReportCheckResult() == ReportCheckResult.VALID) {
			model.addAttribute("jasperReport", resultBean.getReport());
		}
		return "reports/report";
	}
	
	public int safeParseInt(String string) {
		if (string.matches("^[0-9]+$")) {
			try {
				return Integer.valueOf(string);
			} catch (NumberFormatException e) {
				log.warn("Non-numeric string was passed to DashboardController", e); // should never happen
			}
		} else {
			log.warn("Non-numeric string was passed to DashboardController");
		}
		return -1;
	}

}
