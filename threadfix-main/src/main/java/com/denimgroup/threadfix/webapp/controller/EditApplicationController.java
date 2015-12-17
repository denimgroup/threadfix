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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@RestController
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
    private DefaultDefectProfileService defaultDefectProfileService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
    @Autowired
    private TagService tagService;
	@Autowired
	private DefectService defectService;
	@Autowired(required = false)
	private PolicyStatusService policyStatusService;

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
                "repositoryRevision", "repositoryUserName", "repositoryPassword", "repositoryFolder",
                "repositoryType", "skipApplicationMerge", "mainDefaultDefectProfile.id",
				"useDefaultCredentials", "useDefaultProject");
	}

	@JsonView(AllViews.FormInfo.class)
	@RequestMapping(method = RequestMethod.POST)
	public Object processSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Application application,
			BindingResult result, Model model) throws IOException {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return RestResponse.failure("You don't have permission.");
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
		application.setPolicyStatuses(databaseApplication.getPolicyStatuses());

		application.setUserName(databaseApplication.getUserName());
        application.setPassword(databaseApplication.getPassword());
		application.setEncryptedPassword(databaseApplication.getEncryptedPassword());
		application.setEncryptedUserName(databaseApplication.getEncryptedUserName());
		application.setEndpointPermissions(databaseApplication.getEndpointPermissions());
		application.setScans(databaseApplication.getScans());
		application.setTags(databaseApplication.getTags());

		//Edit application after uploading scans: refresh count numbers
		application.setCriticalVulnCount(databaseApplication.getCriticalVulnCount());
		application.setHighVulnCount(databaseApplication.getHighVulnCount());
		application.setMediumVulnCount(databaseApplication.getMediumVulnCount());
		application.setLowVulnCount(databaseApplication.getLowVulnCount());
		application.setInfoVulnCount(databaseApplication.getInfoVulnCount());
		application.setTotalVulnCount(databaseApplication.getTotalVulnCount());

		if (!result.hasErrors()) {
			applicationService.validateAfterEdit(application, result);
		}
		
		if (application.getName() != null && application.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}

        if (application.getRepositoryUrl() != null && !application.getRepositoryUrl().isEmpty() &&
                application.getRepositoryType() == null) {
            result.rejectValue("repositoryType", null, null, "Choose either Git or SVN");
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

			return FormRestResponse.failure("Errors", result);

		} else {
			if (application.getMainDefaultDefectProfile() == null ||
					application.getMainDefaultDefectProfile().getId() == null) {
				application.setMainDefaultDefectProfile(null);
			} else {
				Integer id = application.getMainDefaultDefectProfile().getId();
				DefaultDefectProfile mainDefaultDefectProfile = defaultDefectProfileService.loadDefaultProfile(id);
				application.setMainDefaultDefectProfile(mainDefaultDefectProfile);
			}

			application.setOrganization(organizationService.loadById(application.getOrganization().getId()));
			applicationService.storeApplication(application, EventAction.APPLICATION_EDIT);
            vulnerabilityService.updateOrgsVulnerabilityReport();
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + application.getName() + " (id=" + application.getId() + ") has been edited by user " + user);

			return RestResponse.success(application);
		}
	}
	
	@RequestMapping(value="/wafAjax", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	public Object processSubmitAjaxWaf(@PathVariable("appId") int appId,
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
				
				applicationService.storeApplication(databaseApplication, EventAction.APPLICATION_EDIT);
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

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value="/addDTAjax", method = RequestMethod.POST)
	public Object processSubmitAjaxDefectTracker(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@ModelAttribute Application application,
			BindingResult result, SessionStatus status, Model model,
			HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return RestResponse.failure("You are not authorized to manage this application.");
		}
		
		Application databaseApplication = applicationService.loadApplication(appId);
		if (databaseApplication == null || !databaseApplication.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		databaseApplication.setDefectTracker(application.getDefectTracker());
		databaseApplication.setUserName(application.getUserName());
		databaseApplication.setPassword(application.getPassword());
		databaseApplication.setProjectName(application.getProjectName());
		databaseApplication.setUseDefaultCredentials(application.isUseDefaultCredentials());
		databaseApplication.setUseDefaultProject(application.isUseDefaultProject());

		// This part handles the weird checkbox-unchecked-means-no-angular-property front-end behavior
		boolean hasUseDefaultCredentials = request.getParameterMap().containsKey("useDefaultCredentials");
		boolean hasUseDefaultProduct = request.getParameterMap().containsKey("useDefaultProduct");

		if (!hasUseDefaultCredentials) {
			databaseApplication.setUseDefaultCredentials(false);
		}
		if (!hasUseDefaultProduct) {
			databaseApplication.setUseDefaultProject(false);
		}

		if (!result.hasErrors()) {
			applicationService.validateDefectTracker(databaseApplication, result);
		}
		
		if (databaseApplication.getName() != null && databaseApplication.getName().trim().equals("")
				&& !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
            return FormRestResponse.failure("Invalid data.", result);
			
		} else {
            PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS);

			applicationService.storeApplication(databaseApplication, EventAction.APPLICATION_EDIT);

			defectService.updateScannerSuppliedStatuses(appId);

			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			
			log.debug("The Application " + databaseApplication.getName() + " (id=" + databaseApplication.getId() + ") has been edited by user " + user);

			return RestResponse.success(databaseApplication.getDefectTracker());
		}
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value="/removeDTAjax", method = RequestMethod.POST)
	public Object removeDefectTracker(@PathVariable("appId") int appId,
									  @PathVariable("orgId") int orgId,
									  @ModelAttribute Application application,
									  BindingResult result, SessionStatus status, Model model,
									  HttpServletRequest request){

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			return RestResponse.failure("You are not authorized to manage this application.");
		}
		Application databaseApplication = applicationService.loadApplication(appId);
		if (databaseApplication == null || !databaseApplication.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		databaseApplication.setDefectTracker(null);
		databaseApplication.setUserName(null);
		databaseApplication.setPassword(null);
		databaseApplication.setProjectName(null);
		databaseApplication.setUseDefaultCredentials(false);
		databaseApplication.setUseDefaultProject(false);
		databaseApplication.setProjectId(null);

		PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS);

		applicationService.storeApplication(databaseApplication, EventAction.APPLICATION_EDIT);

		defectService.deleteByApplicationId(databaseApplication.getId());

		if(policyStatusService != null) {
			policyStatusService.runStatusCheck(databaseApplication);
		}

		String user = SecurityContextHolder.getContext().getAuthentication().getName();

		log.debug("The Application " + databaseApplication.getName() + " (id=" + databaseApplication.getId() + ") has been edited by user " + user);

		return RestResponse.success(databaseApplication);
	}

	@RequestMapping(value="/setTagsEndpoint", method = RequestMethod.POST)
    public @ResponseBody RestResponse<List<Tag>> setTagsEndpoint(@PathVariable("appId") int appId,
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
            dbApplication.setTags(cleanTags(newTags));
            applicationService.storeApplication(dbApplication, EventAction.APPLICATION_SET_TAGS);

            return RestResponse.success(newTags);

        } catch (JsonSyntaxException exception) {
            log.warn("JSON Parsing failed.", exception);
            return FormRestResponse.failure("Invalid data.");
        }
    }

	private List<Tag> cleanTags(List<Tag> newTags) {

		List<Tag> returnTags = list();

		for (Tag newTag : newTags) {
			returnTags.add(tagService.loadTag(newTag.getId()));
		}

		return returnTags;
	}
}
