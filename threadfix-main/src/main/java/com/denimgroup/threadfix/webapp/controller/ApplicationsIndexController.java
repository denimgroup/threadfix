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
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.LicenseService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@SessionAttributes(value = {"organization", "application"})
@RequestMapping("/organizations")
public class ApplicationsIndexController {
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}
	
	private final SanitizedLogger log = new SanitizedLogger(ApplicationsIndexController.class);

    @Autowired
	private OrganizationService organizationService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
	private ApplicationCriticalityService applicationCriticalityService;
    @Autowired
    private ScanTypeCalculationService scanTypeCalculationService;
    @Autowired
    private ScanService scanService;
    @Autowired
    private ScanMergeService scanMergeService;
    @Autowired(required = false)
    private LicenseService licenseService;

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
        model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
        model.addAttribute("applicationTypes", FrameworkType.values());

        if (licenseService != null) {
            model.addAttribute("canAddApps", licenseService.canAddApps());
            model.addAttribute("appLimit", licenseService.getAppLimit());
        } else {
            model.addAttribute("canAddApps", true);
        }
		return "organizations/index";
	}

	@RequestMapping(value="/jsonList", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Organization[]> jsonList() {
        List<Organization> organizations = organizationService.loadAllActive();

        if (organizations == null) {
            return RestResponse.failure("No organizations found.");
        } else {
            return RestResponse.success(organizations.toArray(new Organization[organizations.size()]));
        }
	}
	
	@RequestMapping("/{orgId}/getReport")
	public ModelAndView getReport(@PathVariable("orgId") int orgId,
			HttpServletRequest request, Model model) {
		Organization organization = organizationService.loadOrganization(orgId);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
		} else {
			ReportParameters parameters = new ReportParameters();
			parameters.setApplicationId(-1);
			parameters.setOrganizationId(orgId);
			parameters.setFormatId(1);
			parameters.setReportFormat(ReportFormat.POINT_IN_TIME_GRAPH);
			ReportCheckResultBean resultBean = reportsService.generateReport(parameters, request);
			if (resultBean.getReportCheckResult() == ReportCheckResult.VALID) {
				model.addAttribute("jasperReport", resultBean.getReport());
			}
			return new ModelAndView("reports/report");
		}
	}

    /**
     * Allows the user to upload a scan to an existing application channel.
     *
     * @return Team with updated stats.
     */
    @RequestMapping(headers="Accept=application/json", value="/{orgId}/applications/{appId}/upload/remote", method=RequestMethod.POST)
    public @ResponseBody RestResponse<Organization> uploadScan(@PathVariable("appId") int appId, @PathVariable("orgId") int orgId,
                                                       HttpServletRequest request, @RequestParam("file") MultipartFile file) {

        log.info("Received REST request to upload a scan to application " + appId + ".");

        Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));

        if (myChannelId == null) {
            return RestResponse.failure("Failed to determine the scan type.");
        }

        String fileName = scanTypeCalculationService.saveFile(myChannelId, file);

        ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);

        if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
            Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);

            if (scan != null) {
                Organization organization = organizationService.loadOrganization(orgId);
                return RestResponse.success(organization);
            } else {
                return RestResponse.failure("Something went wrong while processing the scan.");
            }
        } else {
            return RestResponse.failure(returnValue.getScanCheckResult().toString());
        }
    }
}
