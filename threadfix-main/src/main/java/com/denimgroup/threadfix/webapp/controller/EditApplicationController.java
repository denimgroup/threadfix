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
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.codehaus.jackson.map.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.validation.Valid;
import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/edit")
@SessionAttributes({"application", "scanParametersBean"})
public class EditApplicationController {
	
	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);

    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private DefectTrackerService defectTrackerService;
    @Autowired
	private WafService wafService;
    @Autowired
	private ApplicationCriticalityService applicationCriticalityService;
    @Autowired
	private OrganizationService organizationService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private TagService tagService;

	@ModelAttribute("defectTrackerList")
	public List<DefectTracker> populateDefectTrackers() {
		return defectTrackerService.loadAllDefectTrackers();
	}

	@ModelAttribute("wafList")
	public List<Waf> populateWafs() {
		return wafService.loadAll();
	}
	
	@ModelAttribute
	public List<ApplicationCriticality> populateApplicationCriticalities() {
		return applicationCriticalityService.loadAll();
	}
	
	@ModelAttribute("teamList")
	public List<Organization> populateTeams() {
		return organizationService.loadAllActive();
	}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTracker.id", "userName",
                "password", "waf.id", "projectName", "projectRoot", "applicationCriticality.id",
                "uniqueId", "organization.id", "frameworkType", "repositoryUrl", "repositoryBranch",
                "repositoryUserName", "repositoryPassword", "repositoryFolder", "skipApplicationMerge");
	}

	@RequestMapping(method = RequestMethod.POST)
	public @ResponseBody String processSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application,
			BindingResult result, Model model) throws IOException {

        ObjectWriter writer = ControllerUtils.getObjectWriter(AllViews.FormInfo.class);

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return writer.writeValueAsString(RestResponse.failure("You don't have permission."));
		}
		
		Application databaseApplication = applicationService.loadApplication(appId);
		if (databaseApplication == null || !databaseApplication.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		// These should not be editable in this method.
		// TODO split into 3 controllers and use setAllowedFields
		application.setWaf(databaseApplication.getWaf());
		application.setDefectTracker(databaseApplication.getDefectTracker());
		application.setUserName(databaseApplication.getUserName());
		application.setPassword(databaseApplication.getPassword());
		
		if(!result.hasErrors()) {
			applicationService.validateAfterEdit(application, result);
		}
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}

		if (result.hasErrors()) {
            PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_DEFECT_TRACKERS,
					Permission.CAN_MANAGE_WAFS);
			
			if (application.getWaf() != null && application.getWaf().getId() == null) {
				application.setWaf(null);
			}
			
			if (application.getDefectTracker() != null &&
					application.getDefectTracker().getId() == null) {
				application.setDefectTracker(null);
			}

			return writer.writeValueAsString(FormRestResponse.failure("Errors", result));

		} else {
			application.setOrganization(organizationService.loadById(application.getOrganization().getId()));
			applicationService.storeApplication(application);
            vulnerabilityService.updateOrgsVulnerabilityReport();
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);

            return writer.writeValueAsString(RestResponse.success(application));
		}
	}
	
	@RequestMapping(value="/wafAjax", method = RequestMethod.POST)
	public @ResponseBody RestResponse<Waf> processSubmitAjaxWaf(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@ModelAttribute Application application,
			BindingResult result, Model model) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return RestResponse.failure("You don't have permission to set the WAF for this application.");
		}

        Waf waf = null;

        if(application != null && application.getId() != null) {
			Application databaseApplication = applicationService.loadApplication(application.getId());
			if (databaseApplication == null) {
				result.rejectValue("waf.id", null, null, "We were unable to retrieve the application.");
			} else {

                Integer newWafId = null;
                if (application.getWaf() != null) {
                    newWafId = application.getWaf().getId();
                }

				if (newWafId == null || newWafId == 0) {
                    // remove any outdated vuln -> waf rule links
                    applicationService.updateWafRules(databaseApplication, newWafId);
					databaseApplication.setWaf(null);
				}
				
				if (newWafId != null && newWafId != 0) {
					waf = wafService.loadWaf(newWafId);
					
					if (waf == null) {
						result.rejectValue("waf.id", "errors.invalid",
								new String [] { "WAF Choice" }, null);
					} else {
                        // remove any outdated vuln -> waf rule links
                        applicationService.updateWafRules(databaseApplication, newWafId);
						databaseApplication.setWaf(waf);
					}
				}
				
				applicationService.storeApplication(databaseApplication);
				String user = SecurityContextHolder.getContext().getAuthentication().getName();
				log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);
				model.addAttribute("application", databaseApplication);
			}
		} else {
			result.rejectValue("waf.id", null, null, "We were unable to retrieve the application.");
            return FormRestResponse.failure("Unable to retrieve the application.", result);
		}
		
		if (result.hasErrors()) {
            return FormRestResponse.failure("Unable to add the WAF. Try again.", result);
		} else {
		    return RestResponse.success(waf);
        }
	}

	@RequestMapping(value="/addDTAjax", method = RequestMethod.POST)
	public @ResponseBody RestResponse<DefectTracker> processSubmitAjaxDefectTracker(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return RestResponse.failure("You are not authorized to manage this application.");
		}
		
		if(!result.hasErrors()) {
			applicationService.validateAfterEdit(application, result);
			applicationService.validateDefectTracker(application, result);
		}
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
            return FormRestResponse.failure("Invalid data.", result);
			
		} else {

            PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS);
			
			applicationService.storeApplication(application);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);

			return RestResponse.success(application.getDefectTracker());
		}
	}

    @RequestMapping(value="/setTagsEndpoint", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Application> setTagsEndpoint(@PathVariable("appId") int appId,
                                                                                    @PathVariable("orgId") int orgId,
                                                                                    @RequestParam("jsonStr") String jsonStr) {
        log.info("Updating tags endpoint");
        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
            return RestResponse.failure("You are not authorized to manage this application.");
        }

        try {
            List<Tag> newTags = new Gson().fromJson(jsonStr, new TypeToken<List<Tag>>(){}.getType());
            Application dbApplication = applicationService.loadApplication(appId);
            if (dbApplication == null) {
                return FormRestResponse.failure("Invalid data.");
            }
            dbApplication.setTags(newTags);
            applicationService.storeApplication(dbApplication);

            return RestResponse.success(dbApplication);

        }    catch (JsonSyntaxException exception) {
            log.warn("JSON Parsing failed.", exception);
            return FormRestResponse.failure("Invalid data.");
        }
    }
}
