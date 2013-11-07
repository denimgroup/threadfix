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

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ReportParameters;
import com.denimgroup.threadfix.data.entities.ReportParameters.ReportFormat;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.report.ReportsService;
import com.denimgroup.threadfix.service.report.ReportsService.ReportCheckResult;

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
	
	public OrganizationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

	private OrganizationService organizationService = null;
	private ReportsService reportsService = null;
	private ApplicationService applicationService = null;
	private ApplicationCriticalityService applicationCriticalityService = null;
	private PermissionService permissionService = null;
	private ChannelTypeService channelTypeService = null;
	private UserService userService = null;
	
	@Autowired
	public OrganizationsController(OrganizationService organizationService,
			ChannelTypeService channelTypeService, PermissionService permissionService,
			ReportsService reportsService, ApplicationService applicationService,
			ApplicationCriticalityService applicationCriticalityService,
			UserService userService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.permissionService = permissionService;
		this.channelTypeService = channelTypeService;
		this.reportsService = reportsService;
		this.userService = userService;
	}

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
				organization.setApplications(permissionService.filterApps(organization));
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
		List<Application> apps = permissionService.filterApps(organization);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,null) &&
				(apps == null || apps.size() == 0)) {
			
			return new ModelAndView("403");
			
		} else {
			ModelAndView mav = new ModelAndView("organizations/detail");
			permissionService.addPermissions(mav, orgId, null,
					Permission.CAN_MANAGE_APPLICATIONS,
					Permission.CAN_MANAGE_TEAMS,
					Permission.CAN_MODIFY_VULNERABILITIES,
					Permission.CAN_GENERATE_REPORTS,
					Permission.CAN_MANAGE_USERS);
			applicationService.generateVulnerabilityReports(organization);
			mav.addObject("apps", apps);
			mav.addObject(organization);
			mav.addObject("application", new Application());
			mav.addObject("applicationTypes", FrameworkType.values());
			mav.addObject("successMessage", ControllerUtils.getSuccessMessage(request));
			if (permissionService.isAuthorized(Permission.CAN_MANAGE_USERS,orgId,null)) {
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
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_TEAMS, orgId, null)) {
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
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
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
		
		if (!permissionService.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
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
			permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS,
					Permission.CAN_MANAGE_WAFS);
			
			model.addAttribute("org",org);
			
			model.addAttribute("canSetDefectTracker", permissionService.isAuthorized(
					Permission.CAN_MANAGE_DEFECT_TRACKERS, orgId, null));
			
			model.addAttribute("canSetWaf", permissionService.isAuthorized(
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
