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
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.LicenseService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@SessionAttributes(value = {"organization", "application"})
@RequestMapping("/organizations")
public class OrganizationsController {
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

    @Autowired
	private OrganizationService organizationService;
    @Autowired
	private ReportsService reportsService;
    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private ApplicationCriticalityService applicationCriticalityService;
    @Autowired
	private ChannelTypeService channelTypeService;
    @Autowired
	private UserService userService;
    @Autowired
    private LicenseService licenseService;

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
		return "organizations/index";
	}
	
	@RequestMapping(value="/withModal", method = RequestMethod.GET)
	public String indexShowModal(HttpServletRequest request) {
		ControllerUtils.addItem(request, "showTeamModal", 1);
		return "redirect:/organizations";
	}
	
	private void addModelObjects(Model model) {
		List<Organization> organizations = organizationService.loadAllActiveFilter();
		
		if (organizations != null) {
			for (Organization organization : organizations) {
				organization.setApplications(PermissionUtils.filterApps(organization));
			}
		}

		// for quick start
		model.addAttribute("channels", channelTypeService.getChannelTypeOptions(null));
		
		applicationService.generateVulnerabilityReports(organizations);
		model.addAttribute(organizations);
		model.addAttribute("application", new Application());
		model.addAttribute("organization", new Organization());
		
		Object userPrincipal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (userPrincipal instanceof ThreadFixUserDetails) {
			model.addAttribute("shouldChangePassword",
					!((ThreadFixUserDetails) userPrincipal).hasChangedInitialPassword());
		}
	}

	@RequestMapping("/{orgId}")
	public ModelAndView detail(@PathVariable("orgId") int orgId,
			HttpServletRequest request) {
		Organization organization = organizationService.loadOrganization(orgId);
		List<Application> apps = PermissionUtils.filterApps(organization);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,null) &&
				(apps == null || apps.size() == 0)) {
			
			return new ModelAndView("403");
			
		} else {
			ModelAndView mav = new ModelAndView("organizations/detail");
            PermissionUtils.addPermissions(mav, orgId, null,
					Permission.CAN_MANAGE_APPLICATIONS,
					Permission.CAN_MANAGE_TEAMS,
					Permission.CAN_MODIFY_VULNERABILITIES,
					Permission.CAN_GENERATE_REPORTS,
					Permission.CAN_MANAGE_USERS);
			applicationService.generateVulnerabilityReports(organization);
			mav.addObject("apps", apps);
			mav.addObject(organization);

            mav.addObject("canAddApps", licenseService.canAddApps());
            mav.addObject("appLimit", licenseService.getAppLimit());

			mav.addObject("application", new Application());
			mav.addObject("applicationTypes", FrameworkType.values());
			mav.addObject("successMessage", ControllerUtils.getSuccessMessage(request));
			if (PermissionUtils.isAuthorized(Permission.CAN_MANAGE_USERS,orgId,null)) {
				mav.addObject("users", userService.getPermissibleUsers(orgId, null));
			}
			return mav;
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
	
	@RequestMapping("/teamTable")
	public String teamTable(Model model, HttpServletRequest request) {
		addModelObjects(model);
        model.addAttribute("canAddApps", licenseService.canAddApps());
        model.addAttribute("appLimit", licenseService.getAppLimit());
		model.addAttribute("applicationTypes", FrameworkType.values());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("contentPage", "organizations/indexTeamTable.jsp");
		model.addAttribute("showTeamModal", ControllerUtils.getItem(request, "showTeamModal"));
		return "ajaxSuccessHarness";
	}

	@RequestMapping("/{orgId}/delete")
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TEAMS')")
	public String deleteOrg(@PathVariable("orgId") int orgId, SessionStatus status,
			HttpServletRequest request) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_TEAMS, orgId, null)) {
			return "403";
		}
			
		Organization organization = organizationService.loadOrganization(orgId);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else {
			
			String teamName = organization.getName();
			organizationService.deactivateOrganization(organization);
			log.info("Organization soft deletion was successful on Organization " + organization.getName() + ".");
			ControllerUtils.addSuccessMessage(request,
					"Team " + teamName + " has been deleted successfully.");
			return "redirect:/organizations";
		}
	}

	@RequestMapping(value="/{orgId}/modalAddApp", method = RequestMethod.POST)
	public String submitAppFromDetailPage(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application, BindingResult result,
			SessionStatus status, Model model, HttpServletRequest request) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
			return "403";
		}

		if (!licenseService.canAddApps()) {
            return "403";
        }

		Organization team = organizationService.loadOrganization(orgId);
		
		if (team == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
		}
		
		String referrer = request.getHeader("referer");
		boolean detailPage = referrer.contains("/organizations/");
		
		String submitResult = submitApp(orgId, application,result,status,model,request);
		
		if (submitResult.equals("Success")) {
			if (detailPage) {
				status.setComplete();
				model.addAttribute("contentPage", "/organizations/" + orgId);
				return "ajaxRedirectHarness";
			} else {
				return teamTable(model,request);
			}
		} else {
			model.addAttribute("organization", team);
			
			return submitResult;
		}
	}
	
	public String submitApp(@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application, BindingResult result,
			SessionStatus status, Model model, HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
			return "403";
		}
		Organization org = null;
		if (application.getOrganization() == null) {
			org = organizationService.loadOrganization(orgId);
			if (org != null) {
				application.setOrganization(org);
			}
		} else {
			org = application.getOrganization();
		}
		
		applicationService.validateAfterCreate(application, result);
		
		if (result.hasErrors()) {
            PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS,
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("org",org);
            model.addAttribute("applicationTypes", FrameworkType.values());
			model.addAttribute("canSetDefectTracker", PermissionUtils.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, null));
			
			model.addAttribute("canSetWaf", PermissionUtils.isAuthorized(
					Permission.CAN_MANAGE_WAFS, orgId, null));
			
			model.addAttribute("contentPage", "applications/forms/newApplicationForm.jsp");
			
			return "ajaxFailureHarness";
		} else {

			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("User " + user + " has created an Application with the name " + application.getName() +
					", the ID " + application.getId() +
					", and the Organization " + application.getOrganization().getName());
			
			ControllerUtils.addSuccessMessage(request,
					"Application " + application.getName() + " was successfully created in team " +
					application.getOrganization().getName() + ".");
			
			return "Success";
		}
	}
		
}
