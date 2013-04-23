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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.VulnerabilityCommentService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.report.ReportsService.ReportFormat;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController {
	
	public DashboardController(){}
	
	private VulnerabilityCommentService vulnerabilityCommentService;
	private ScanService scanService;
	private ReportsService reportsService;

	@Autowired
	public DashboardController(ScanService scanService,
			ReportsService reportsService,
			PermissionService permissionService,
			ApplicationService applicationService,
			VulnerabilityCommentService vulnerabilityCommentService){
		this.vulnerabilityCommentService = vulnerabilityCommentService;
		this.scanService = scanService;
		this.reportsService = reportsService;
	}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request, HttpServletResponse response) {
		log.info("Hit the dashboard");
		
		model.addAttribute("recentComments", vulnerabilityCommentService.loadMostRecent());
		model.addAttribute("recentScans", scanService.loadMostRecent());
		ReportParameters parameters = new ReportParameters();
		parameters.setApplicationId(-1);
		parameters.setOrganizationId(-1);
		parameters.setFormatId(1);
		parameters.setReportFormat(ReportFormat.POINT_IN_TIME_GRAPH);
		ReportCheckResultBean resultBean = reportsService.generateReport(parameters, request, response);
		
		if (resultBean.getReportCheckResult() == ReportCheckResult.VALID) {
			model.addAttribute("pointInTimeReport", resultBean.getReport());
		}
		
		return "dashboard/dashboard";
	}
	
	@RequestMapping(value="/leftReport", method=RequestMethod.POST)
	public String leftReport(Model model, HttpServletRequest request, HttpServletResponse response) {
		return report(model, request, response, ReportFormat.SIX_MONTH_SUMMARY);
	}
	
	@RequestMapping(value="/rightReport", method=RequestMethod.POST)
	public String rightReport(Model model, HttpServletRequest request, HttpServletResponse response) {
		return report(model, request, response, ReportFormat.TOP_TEN_APPS);
	}
	
	public String report(Model model, HttpServletRequest request, HttpServletResponse response, ReportFormat reportFormat) {
		log.info("hit report ajax");
		ReportParameters parameters = new ReportParameters();
		parameters.setApplicationId(-1);
		parameters.setOrganizationId(-1);
		parameters.setFormatId(1);
		parameters.setReportFormat(reportFormat);
		ReportCheckResultBean resultBean = reportsService.generateReport(parameters, request, response);
		if (resultBean.getReportCheckResult() == ReportCheckResult.VALID) {
			model.addAttribute("jasperReport", resultBean.getReport());
		}
		return "reports/report";
	}

}
