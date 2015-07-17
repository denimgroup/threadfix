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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;


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
    @Autowired(required = false)
    private LicenseService licenseService;
    @Autowired
    private TagService tagService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@RequestMapping(value = "/teams", method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
        model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
        model.addAttribute("applicationTypes", FrameworkType.values());
        model.addAttribute("tags", tagService.loadAllApplicationTags());

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
	@JsonView(AllViews.ApplicationIndexView.class)
	public @ResponseBody Object jsonList() {
        List<Organization> organizations = organizationService.loadAllActiveFilter();

        organizations = PermissionUtils.filterTeamList(organizations);
        if (organizations == null) {
            return failure("No organizations found.");
        } else {
            Map<String, Object> map = map();

            map.put("teams", organizations);
            map.put("genericSeverities", genericSeverityService.loadAll());
            map.put("canEditIds", PermissionUtils.getIdsWithPermission(Permission.CAN_MANAGE_APPLICATIONS, organizations));
            map.put("canUploadIds", PermissionUtils.getAppIdsWithPermission(Permission.CAN_UPLOAD_SCANS, organizations));

            return RestResponse.success(map);
        }
	}

	@RequestMapping("/organizations/{orgId}/getReport")
	public @ResponseBody RestResponse<List<Map<String, Object>>> getReport(@PathVariable("orgId") int orgId,
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
			ReportCheckResultBean resultBean = reportsService.generateDashboardReport(parameters, request);
			return RestResponse.success(resultBean.getReportList());
		}
	}

	@RequestMapping(value = "/organizations/{orgId}/search", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object search(@PathVariable("orgId") int orgId, HttpServletRequest request) {
		List<Application> apps = organizationService.search(orgId, request);

		return RestResponse.success(CollectionUtils.map(
				"applications", apps,
				"countApps", organizationService.countApps(orgId, request.getParameter("searchString"))));
	}
}
