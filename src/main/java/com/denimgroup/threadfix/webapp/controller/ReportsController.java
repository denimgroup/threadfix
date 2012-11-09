////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.webapp.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.report.ReportsService;

@Controller
@RequestMapping("/reports")
@PreAuthorize("hasRole('ROLE_CAN_GENERATE_REPORTS')")
public class ReportsController {
	
	private final SanitizedLogger log = new SanitizedLogger(ReportsController.class);

	private OrganizationService organizationService;
	private PermissionService permissionService;
	private ApplicationService applicationService;
	private ReportsService reportsService;

	@Autowired
	public ReportsController(OrganizationService organizationService,
			PermissionService permissionService,
			ApplicationService applicationService, 
			ReportsService reportsService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.permissionService = permissionService;
		this.reportsService = reportsService;
	}

	public ReportsController(){}
	
	@ModelAttribute("organizationList")
	public List<Organization> getOrganizations() {
		List<Organization> organizationList = organizationService.loadAllActiveFilter();
		return organizationList;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(ModelMap model, HttpServletRequest request) {
		
		if (request != null && request.getSession() != null && 
				request.getSession().getAttribute("reportsError") != null) {
			model.addAttribute("error", request.getSession().getAttribute("reportsError"));
			request.getSession().removeAttribute("reportsError");
		}
		
		model.addAttribute(new ReportParameters());
		return "reports/index";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processSubmit(ModelMap model, @ModelAttribute ReportParameters reportParameters,
			BindingResult result, SessionStatus status, HttpServletRequest request, 
			HttpServletResponse response) throws IOException{
		String reportFile = null;

		if (reportParameters.getReportId() < 0 || reportParameters.getReportId() > 8) {
			log.warn("An incorrect report ID was passed through, returning an error page.");
			request.getSession().setAttribute("reportsError", "An invalid report type was chosen.");
			return "redirect:/reports";
		}
		
		List<Integer> applicationIdList = getApplicationIdList(reportParameters);

		if (applicationIdList == null || applicationIdList.isEmpty()) {
			request.getSession().setAttribute("reportsError", "You must select at least one application.");
			return "redirect:/reports";
		}
		
		if ((reportParameters.getReportId() == 1 || reportParameters.getReportId() == 7)
				&& reportParameters.getFormatId() == 2) {
			request.getSession().setAttribute("reportsError", "The CSV format is not available for this report.");
			return "redirect:/reports";
		}
		
		switch (reportParameters.getReportId()) {
		case 1:
			reportFile = "trending.jrxml";
			break;
		case 2:
			reportFile = "pointInTime.jrxml";
			break;
		case 3:
			reportFile = "cwe.jrxml";
			break;
		case 4:
			reportFile = "cweChannel.jrxml";
			break;
		case 5:
			reportFile = "scannerComparison.jrxml";
			break;
		case 6:
			return scannerComparisonByVulnerability(model, applicationIdList);
		case 7:
			reportFile = "monthlyBarChart.jrxml";
			break;
		case 8:
			// TODO probably do this in a more idiomatic way
			return new PortfolioReportController(organizationService).index(
					model, request, reportParameters.getOrganizationId());
		}

		log.info("About to generate report for " + applicationIdList.size() + " applications.");

		Map<String, Object> params = new HashMap<String, Object>();
		params.put("appId", applicationIdList);
		String path = request.getSession().getServletContext().getRealPath("/");
		StringBuffer report = null;
		
		if(reportParameters.getFormatId() == 2) {
			report = reportsService.getReport(path, reportFile, "CSV", params, applicationIdList, response);
			String pageString = report.toString();
			response.setContentType("application/octet-stream");
			response.setHeader("Content-Disposition", "attachment; filename=\"report_csv_" + applicationIdList
					+ ".csv\"");

			ServletOutputStream out = response.getOutputStream();

			InputStream in = new ByteArrayInputStream(pageString.getBytes("UTF-8"));

			byte[] outputByte = new byte[65535];
			
			int remainingSize = in.read(outputByte, 0, 65535);
			
			// copy binary content to output stream
			while (remainingSize != -1) {
				out.write(outputByte, 0, remainingSize);
				remainingSize = in.read(outputByte, 0, 65535);
			}
			in.close();
			out.flush();
			out.close();
			return null;
		
		} else if(reportParameters.getFormatId() == 3) {
			report = reportsService.getReport(path, reportFile, "PDF", params, applicationIdList, response);
			return null;
			
		} else //Output is HTML
			report = reportsService.getReport(path, reportFile, "HTML", params, applicationIdList, response);
		
		model.addAttribute("jasperReport", report);
		
		if (report != null) {
			log.info("Finished generating report.");
			return "reports/report";
		} else {
			log.warn("Failed to generate report.");
			request.getSession().setAttribute("reportsError", "There was an error generating the report.");
			return "redirect:/reports";
		}
	}
	
	public List<Integer> getApplicationIdList(ReportParameters reportParameters) {
		List<Integer> applicationIdList = new ArrayList<Integer>();
		Set<Integer> teamIds = permissionService.getAuthenticatedTeamIds();

		if (reportParameters.getOrganizationId() < 0) {
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList = applicationService.loadAllActiveFilter(teamIds);
				for (Application app : appList) {
					applicationIdList.add(app.getId());
				}
			} else {
				applicationIdList.add(reportParameters.getApplicationId());
			}
		} else if (hasGlobalPermission(Permission.READ_ACCESS) ||
				teamIds.contains(reportParameters.getOrganizationId())) {
			Organization org = organizationService.loadOrganization(reportParameters.getOrganizationId());
			if (reportParameters.getApplicationId() < 0) {
				List<Application> appList = org.getActiveApplications();
				for (Application app : appList) {
					if (app.isActive()) {
						applicationIdList.add(app.getId());
					}
				}
			} else {
				applicationIdList.add(reportParameters.getApplicationId());
			}
		}
		
		return applicationIdList;
	}
	
	public boolean hasGlobalPermission(Permission permission) {
		return SecurityContextHolder.getContext().getAuthentication()
				.getAuthorities().contains(new GrantedAuthorityImpl(permission.getText()));
	}
	
	
	// TODO rethink some of this - it's a little slow at a few hundred vulns. 
	// The emphasis on genericism through the design makes it harder to pull channel-specific info from vulns.
	public String scannerComparisonByVulnerability(ModelMap model, List<Integer> applicationIdList) {		
		
		if (model == null || applicationIdList == null || applicationIdList.isEmpty()) {
			// This should have been caught earlier
			return "redirect:/reports";
		}
		
		List<List<String>> tableListOfLists = new ArrayList<List<String>>();
		List<String> headerList = new ArrayList<String>(); // this facilitates headers
		List<Application> applicationList = new ArrayList<Application>();
		
		// this map is used to insert the value into the correct space.
		Map<Integer, Integer> channelIdToTablePositionMap = new HashMap<Integer, Integer>();
		
		// positions 0, 1, and 2 are the generic name, path, and parameter of the vulnerability.
		// 3 is open status
		// This also represents the number of headers.
		int columnCount = 4;
				
		for (int id : applicationIdList) {
			Application application = applicationService.loadApplication(id);
			
			if (application == null || application.getChannelList() == null 
					|| application.getVulnerabilities() == null)
				continue;
			applicationList.add(application);
						
			for (ApplicationChannel channel : application.getChannelList()) {
				if (channel == null || channel.getScanCounter() == null
						|| channel.getChannelType() == null 
						|| channel.getChannelType().getId() == null
						|| channel.getChannelType().getName() == null)
					continue;
				
				int channelTypeId = channel.getChannelType().getId();
				
				if (!channelIdToTablePositionMap.containsKey(channelTypeId)) {
					headerList.add(channel.getChannelType().getName());
					channelIdToTablePositionMap.put(channelTypeId, columnCount++);
				}
			}
		}
		
		for (Application application : applicationList) {
			for (Vulnerability vuln : application.getVulnerabilities()) {
				if (vuln == null || vuln.getFindings() == null
						|| (!vuln.isActive() && !vuln.getIsFalsePositive())) {
					continue;
				}
				
				List<String> tempList = new ArrayList<String>(columnCount);
				
				String falsePositive = vuln.getIsFalsePositive() ? "FP" : "OPEN";

				tempList.addAll(Arrays.asList(vuln.getGenericVulnerability().getName(),
											  vuln.getSurfaceLocation().getPath(), 
											  vuln.getSurfaceLocation().getParameter(),
											  falsePositive));
				
				for (int i = 4; i < columnCount; i++) {
					tempList.add(" ");
				}
				
				// For each finding, if the path to the channel type ID is not null, put an X in the table
				for (Finding finding : vuln.getFindings()) {
					if (finding != null && finding.getScan() != null 
							&& finding.getScan().getApplicationChannel() != null 
							&& finding.getScan().getApplicationChannel().getChannelType() != null
							&& finding.getScan().getApplicationChannel().getChannelType().getId() != null) 
					{
						Integer tablePosition = channelIdToTablePositionMap.get(
								finding.getScan().getApplicationChannel().getChannelType().getId());
						if (tablePosition != null) {
							tempList.set(tablePosition, "X");
						}
					}
				}
				
				tableListOfLists.add(tempList);
			}
		}
		
		model.addAttribute("headerList", headerList);
		model.addAttribute("listOfLists", tableListOfLists);
		model.addAttribute("columnCount", columnCount);
				
		return "reports/scannerComparisonByVulnerability";
	}
	
}