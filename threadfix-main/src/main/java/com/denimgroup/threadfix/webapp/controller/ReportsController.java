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
import com.denimgroup.threadfix.data.enums.TagEnum;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.EnterpriseTagService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
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
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Controller
@RequestMapping("/reports")
@PreAuthorize("hasRole('ROLE_CAN_GENERATE_REPORTS')")
public class ReportsController {
	
	private static final String RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String RANDOM_PROVIDER = "SUN";
	
	private final SanitizedLogger log = new SanitizedLogger(ReportsController.class);

    @Autowired
	private OrganizationService organizationService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
	private VulnerabilityService vulnerabilityService;

	private SecureRandom random;

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

	@RequestMapping(value="/ajax/export/{applicationId}/{organizationId}/{reportId}/{formatId}", method = RequestMethod.GET)
    public String processExportRequest(Model model, HttpServletRequest request,
                                       @PathVariable int applicationId,
                                       @PathVariable int organizationId,
                                       @PathVariable int reportId,
                                       @PathVariable int formatId,
                                       HttpServletResponse response) throws IOException {

        if (!PermissionUtils.isAuthorized(Permission.CAN_GENERATE_REPORTS, applicationId, organizationId)) {
            return "403";
        }

        ReportParameters reportParameters = new ReportParameters();
        reportParameters.setApplicationId(applicationId);
        reportParameters.setOrganizationId(organizationId);
        reportParameters.setFormatId(formatId);
        reportParameters.setReportId(reportId);

        return processExportRequest(model, reportParameters, request, response);
    }

	public String processExportRequest(Model model, ReportParameters reportParameters,
                                       HttpServletRequest request,
                                       HttpServletResponse response) throws IOException {

		ReportCheckResultBean reportCheckResultBean = reportsService.generateReport(reportParameters,
				request);
		
		ReportCheckResult reportCheckResult;
		
		if (reportCheckResultBean != null) {
			reportCheckResult = reportCheckResultBean.getReportCheckResult();
		} else {
			reportCheckResult = ReportCheckResult.OTHER_ERROR;
		}
		
		if (reportCheckResult == ReportCheckResult.VALID) {
			boolean isPdf = reportParameters.getFormatId() == 3;
			
			String fileName;
			InputStream in = null;
			
			if (isPdf) {
				response.setContentType("application/pdf");
                fileName = reportsService.getExportFileName(reportParameters) + ".pdf";
				if (reportCheckResultBean.getReportBytes() != null) {
					in = new ByteArrayInputStream(reportCheckResultBean.getReportBytes());
				}
			} else {
				response.setContentType("application/octet-stream");
                fileName = reportsService.getExportFileName(reportParameters) + ".csv";
				StringBuffer report = reportCheckResultBean.getReport();
				if (report != null) {
					String pageString = report.toString();
                    in = new ByteArrayInputStream(pageString.getBytes("UTF-8"));
				}
			}
			
			response.setHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");

			if (in != null) {
				ServletOutputStream out = response.getOutputStream();

				byte[] outputByteBuffer = new byte[65535];
				
				int remainingSize = in.read(outputByteBuffer, 0, 65535);
				
				// copy binary content to output stream
				while (remainingSize != -1) {
					out.write(outputByteBuffer, 0, remainingSize);
					remainingSize = in.read(outputByteBuffer, 0, 65535);
				}
				in.close();
				out.flush();
				out.close();
				return null;
			} else {
				log.warn("Unable to find data for report.");
				return returnError(request, model, ReportCheckResult.OTHER_ERROR);
			}
		}
		
		return returnError(request, model, reportCheckResult);
	}

	@RequestMapping(value="/ajax", method = RequestMethod.POST)
	public String processSubmit(Model model, @ModelAttribute ReportParameters reportParameters,
			HttpServletRequest request, HttpServletResponse response) throws IOException {
		
		// reroute if it's scanner comparison or portfolio report
        if (reportParameters.getReportFormat() == ReportFormat.PORTFOLIO_REPORT) {
			return new PortfolioReportController(organizationService).index(
                    model, request, reportParameters.getOrganizationId());
		}

		if (reportParameters.getFormatId() != 1) {
			return processExportRequest(model, reportParameters, request, response);
		}
		
		ReportCheckResultBean reportCheckResultBean = reportsService.generateReport(reportParameters,
				request);
		
		ReportCheckResult reportCheckResult = reportCheckResultBean.getReportCheckResult();
		
		if (reportCheckResult == ReportCheckResult.VALID) {
			boolean csvEnabled = !(reportParameters.getReportFormat() == ReportFormat.TRENDING || 
					reportParameters.getReportFormat() == ReportFormat.MONTHLY_PROGRESS_REPORT);
			StringBuffer report = reportCheckResultBean.getReport();
			
			if (report != null) {
				log.info("Finished generating report.");
				model.addAttribute("jasperReport", addParameterToReport(report));
				model.addAttribute("csvEnabled", csvEnabled);
				model.addAttribute("pdfEnabled", true);
				model.addAttribute("reportId",reportParameters.getReportId());
				return "reports/report";
				
			} else {
				log.warn("Failed to generate report.");
				ControllerUtils.addErrorMessage(request, "There was an error generating the report.");
				model.addAttribute("contentPage", "/reports");
				return "ajaxRedirectHarness";
			}
		} else {
			return returnError(request, model, reportCheckResult);
		}
	}

    @RequestMapping(value="/ajax/page", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<Map<String, Object>> processSubmitPage(Model model, @ModelAttribute ReportParameters reportParameters,
                                HttpServletRequest request, HttpServletResponse response) throws IOException {

		if (reportParameters.getReportFormat() == ReportFormat.CHANNEL_COMPARISON_DETAIL) {
			return RestResponse.success(reportsService.scannerComparisonByVulnerability(model, reportParameters));
		}
        else if (reportParameters.getReportFormat() == ReportFormat.VULNERABILITY_LIST) {
			model.addAttribute("reportId",reportParameters.getReportId());
			return RestResponse.success(reportsService.vulnerabilityList(model, reportParameters));
		}

        return null;
    }

	//	TODO - Move the creation of SecureRandoms into some sort of shared facility
	//	for the entire application (each class doesn't need to repeat this code)
	private SecureRandom getRandomSource() {
        if (this.random == null) {
			try {
				this.random = SecureRandom.getInstance(RANDOM_ALGORITHM, RANDOM_PROVIDER);
			} catch (NoSuchAlgorithmException e) {
				log.error("Unable to find algorithm " + RANDOM_ALGORITHM, e);
			} catch (NoSuchProviderException e) {
				log.error("Unable to find provider " + RANDOM_PROVIDER, e);
			}
        }
        return(this.random);
	}
	
	private String addParameterToReport(StringBuffer buffer) {
		String resultString = buffer.toString();
		String regex = "(.*<img [^>]*img_[^\"]*)(.*)";
		return resultString.replaceAll(regex, "$1?" + getRandomSource().nextInt() + "$2");
	}
	
	private String returnError(HttpServletRequest request, Model model,
			ReportCheckResult reportCheckResult) {
		if (reportCheckResult == ReportCheckResult.BAD_REPORT_TYPE) {
			return incorrectReportIdError(request, model);
		} else if (reportCheckResult == ReportCheckResult.NO_APPLICATIONS) {
			return missingApplicationsError(request, model);
		} else {
			return exceptionError(request, model);
		}
	}
	
	private String incorrectReportIdError(HttpServletRequest request, Model model) {
		log.warn("An incorrect report ID was passed through, returning an error page.");
		ControllerUtils.addErrorMessage(request, "An invalid report type was chosen.");
		return redirect(model);
	}
	
	private String missingApplicationsError(HttpServletRequest request, Model model) {
		ControllerUtils.addErrorMessage(request, "You must select at least one application.");
		return redirect(model);
	}
	
	private String exceptionError(HttpServletRequest request, Model model) {
		ControllerUtils.addErrorMessage(request, "An error occurred while generating the report. " +
				"Check the logs for more details.");
		return redirect(model);
	}
	
	private String redirect(Model model) {
		model.addAttribute("contentPage", "/reports");
		return "ajaxRedirectHarness";
	}

}