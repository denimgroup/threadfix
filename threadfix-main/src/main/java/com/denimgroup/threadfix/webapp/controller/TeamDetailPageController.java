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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.LicenseService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import org.codehaus.jackson.map.ObjectWriter;
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
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author mcollins
 *
 */
@Controller
@SessionAttributes(value = {"organization", "application"})
@RequestMapping("/organizations/{orgId}")
public class TeamDetailPageController {

    @ModelAttribute
    public List<ApplicationCriticality> populateApplicationCriticalities() {
        return applicationCriticalityService.loadAll();
    }

    private final SanitizedLogger log = new SanitizedLogger(TeamDetailPageController.class);

    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private ApplicationCriticalityService applicationCriticalityService;
    @Autowired
    private UserService userService;
    @Autowired(required = false)
    private LicenseService licenseService;

    @RequestMapping(method=RequestMethod.GET)
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
            mav.addObject("apps", apps);
            mav.addObject(organization);

            if (licenseService != null) {
                mav.addObject("canAddApps", licenseService.canAddApps());
                mav.addObject("appLimit", licenseService.getAppLimit());
            } else {
                mav.addObject("canAddApps", true);
            }

            mav.addObject("application", new Application());
            mav.addObject("applicationTypes", FrameworkType.values());
            mav.addObject("successMessage", ControllerUtils.getSuccessMessage(request));
            if (PermissionUtils.isAuthorized(Permission.CAN_MANAGE_USERS,orgId,null)) {
                mav.addObject("users", userService.getPermissibleUsers(orgId, null));
            }
            return mav;
        }
    }

    @RequestMapping(value="/info", method=RequestMethod.GET)
    public @ResponseBody String getInfo(@PathVariable int orgId) throws IOException {
        final RestResponse<? extends Object> restResponse;

        Organization organization = organizationService.loadOrganization(orgId);
        List<Application> apps = PermissionUtils.filterApps(organization);

        if (organization == null){
            restResponse = RestResponse.failure("Unable to find the requested team.");
        } else if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, null) &&
                (apps == null || apps.size() == 0)) {
            restResponse = RestResponse.failure("You don't have permission to see that object.");
        } else {
            Map<String, Object> map = new HashMap<>();
            map.put("team", organization);
            map.put("applications", apps);
            restResponse = RestResponse.success(map);
        }

        ObjectWriter writer = ControllerUtils.getObjectWriter(AllViews.TableRow.class);

        return writer.writeValueAsString(restResponse);
    }


    @RequestMapping("/delete")
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
            return "redirect:/";
        }
    }

    @RequestMapping(value="/modalAddApp", method = RequestMethod.POST, consumes="application/x-www-form-urlencoded",
            produces="application/json")
    public @ResponseBody RestResponse<Application> submitAppFromDetailPage(@PathVariable("orgId") int orgId,
               @Valid @ModelAttribute Application application, BindingResult result,
               Model model) {
        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
            return RestResponse.failure("Permissions Failure");
        }

        Organization team = organizationService.loadOrganization(orgId);

        if (team == null) {
            log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
            throw new ResourceNotFoundException();
        }

        String submitResult = submitApp(orgId, application,result,model);

        if (submitResult.equals("Success")) {
            log.info("Successfully created application " + application.getName() + " in team " + team.getName());

            model.addAttribute("application", new Application());

            return RestResponse.success(application);
        } else {
            model.addAttribute("organization", team);

            return FormRestResponse.failure(submitResult, result);
        }
    }

    public String submitApp(int orgId, @Valid @ModelAttribute Application application,
                            BindingResult result, Model model) {

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, null)) {
            return "403";
        }
        Organization org;
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

            return "Success";
        }
    }
}