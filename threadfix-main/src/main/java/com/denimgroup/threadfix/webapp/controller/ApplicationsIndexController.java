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

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;
import static com.denimgroup.threadfix.service.util.ControllerUtils.writeSuccessObjectWithView;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@SessionAttributes(value = {"organization", "application"})
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

	@RequestMapping(value = "/teams", method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
        model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
        model.addAttribute("applicationTypes", FrameworkType.values());

        if (licenseService != null) {
            model.addAttribute("underEnterpriseLimit", licenseService.canAddApps());
            model.addAttribute("canManageTeams", PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_TEAMS));
            model.addAttribute("appLimit", licenseService.getAppLimit());
        } else {
            model.addAttribute("canManageTeams");
            model.addAttribute("underEnterpriseLimit", true);
        }
		return "organizations/index";
	}

	@RequestMapping(value="/organizations/jsonList", method = RequestMethod.GET)
	public @ResponseBody Object jsonList() {
        List<Organization> organizations = organizationService.loadAllActiveFilter();

        organizations = PermissionUtils.filterTeamList(organizations);
        if (organizations == null) {
            return failure("No organizations found.");
        } else {
            Map<String, Object> map = newMap();

            map.put("teams", organizations);
            map.put("canEditIds", PermissionUtils.getIdsWithPermission(Permission.CAN_MANAGE_APPLICATIONS, organizations));
            map.put("canUploadIds", PermissionUtils.getAppIdsWithPermission(Permission.CAN_UPLOAD_SCANS, organizations));

            return writeSuccessObjectWithView(map, AllViews.TableRow.class);
        }
	}

	@RequestMapping("/organizations/{orgId}/getReport")
	public ModelAndView getReport(@PathVariable("orgId") int orgId,
			HttpServletRequest request, Model model) {
		Organization organization = organizationService.loadById(orgId);
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
     * Allows the user to upload a scan to an existing application.
     *
     * @return Team with updated stats.
     */
    @RequestMapping(headers="Accept=application/json", value="/organizations/{orgId}/applications/{appId}/upload/remote", method=RequestMethod.POST)
    public @ResponseBody RestResponse<Organization> uploadScan(@PathVariable("appId") int appId, @PathVariable("orgId") int orgId,
                                                       HttpServletRequest request, @RequestParam("file") MultipartFile file) {

        log.info("Received REST request to upload a scan to application " + appId + ".");

        if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)){
            return failure("You don't have permission to upload scans.");
        }

        Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));

        if (myChannelId == null) {
            return failure("Failed to determine the scan type.");
        }

        String fileName = scanTypeCalculationService.saveFile(myChannelId, file);

        ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);

        if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
            Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);

            if (scan != null) {
                Organization organization = organizationService.loadById(orgId);
                return success(organization);
            } else {
                return failure("Something went wrong while processing the scan.");
            }
        } else {
            return failure(returnValue.getScanCheckResult().toString());
        }
    }
}
