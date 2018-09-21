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

import com.denimgroup.threadfix.DiskUtils;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.DefectTrackerBean;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.viewmodels.ProjectMetadata;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.viewmodels.DefectViewModel;
import com.denimgroup.threadfix.webapp.viewmodels.VulnerabilityCollectionModel;
import com.fasterxml.jackson.annotation.JsonView;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;


@Controller
@RequestMapping("/organizations/{orgId}/applications")
@SessionAttributes({"defectTracker", "application", "waf", "defectViewModel", "scanParametersBean"})
public class ApplicationsController {

    public ApplicationsController(){}

	private final SanitizedLogger log = new SanitizedLogger(ApplicationsController.class);

    private static final String ERROR_MSG = "error_msg";

    @Autowired
	private FindingService findingService;
    @Autowired
    private GenericVulnerabilityService genericVulnerabilityService;
    @Autowired
	private ApplicationCriticalityService applicationCriticalityService;
    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private DefectTrackerService defectTrackerService;
    @Autowired
	private WafService wafService;
    @Autowired
	private OrganizationService organizationService;
    @Autowired
	private UserService userService;
    @Autowired
	private ChannelVulnerabilityService channelVulnerabilityService;
    @Autowired
    private ChannelTypeService channelTypeService;
    @Autowired
    private TagService tagService;
    @Autowired
    private DefaultConfigService defaultConfigService;
    @Autowired
    private CacheBustService cacheBustService;
    @Autowired(required = false)
    private PolicyStatusService policyStatusService;
    @Autowired(required = false)
    private PolicyService policyService;


	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@RequestMapping("/{appId}")
	public String detail(@PathVariable("orgId") Integer orgId, @PathVariable("appId") Integer appId,
			Model model, HttpServletRequest request) {
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		TableSortBean falsePositiveBean = new TableSortBean();
		falsePositiveBean.setFalsePositive(true);
		
		long numVulns = applicationService.getVulnCount(appId, true);
		long numClosedVulns = applicationService.getVulnCount(appId, false);
		long falsePositiveCount = applicationService.getCount(appId, falsePositiveBean);
		
		TableSortBean hiddenBean = new TableSortBean();
		hiddenBean.setHidden(true);
		
        PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS,
                Permission.CAN_UPLOAD_SCANS,
                Permission.CAN_MODIFY_VULNERABILITIES,
                Permission.CAN_MANAGE_VULN_FILTERS,
                Permission.CAN_SUBMIT_DEFECTS,
                Permission.CAN_SUBMIT_COMMENTS,
                Permission.CAN_GENERATE_REPORTS,
                Permission.CAN_MANAGE_DEFECT_TRACKERS,
                Permission.CAN_MANAGE_GRC_TOOLS,
                Permission.CAN_MANAGE_USERS,
                Permission.CAN_MANAGE_TAGS);
		
		if (application.getPassword() != null && !"".equals(application.getPassword())) {
			application.setPassword(Application.TEMP_PASSWORD);
		}

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        model.addAttribute("config", config);
        model.addAttribute("reportJsPaths", cacheBustService.notCachedJsPaths(request, config.getApplicationReports()));
        model.addAttribute("tagList", application.getTags());
		model.addAttribute("urlManualList", findingService.getAllManualUrls(appId));
		model.addAttribute("numVulns", numVulns);
		model.addAttribute("defectTracker", new DefectTracker());
		model.addAttribute("waf", new Waf());
		model.addAttribute("newWaf", new Waf());
        model.addAttribute("scanQueueTask", new ScanQueueTask());
		model.addAttribute(new VulnerabilityCollectionModel());
        model.addAttribute("activeTab", getActiveTab(request, falsePositiveCount, numClosedVulns));
		model.addAttribute(application);
		model.addAttribute("finding", new Finding());
		model.addAttribute(new DefectViewModel());
        model.addAttribute("isEnterprise", EnterpriseTest.isEnterprise());
		if (EnterpriseTest.isEnterprise()) {
            if (PermissionUtils.isAuthorized(Permission.CAN_MANAGE_USERS, orgId, appId)
                    || PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
                model.addAttribute("users", userService.getPermissibleUsers(orgId, appId));
            }
        }
		model.addAttribute("manualChannelVulnerabilities", genericVulnerabilityService.loadAll());
        addAttrForScheduledScanTab(model);
		return "applications/detail";
	}

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping("{appId}/policyStatus")
    public @ResponseBody RestResponse getPolicyStatus(@PathVariable("appId") Integer appId) throws IOException {

        Application application = applicationService.loadApplication(appId);

        if (policyStatusService != null) {
            return success(map(
                    "passFilters", policyStatusService.passFilters(application),
                    "policyStatuses", application.getPolicyStatuses()
            ));
        } else {
            return failure("No Policy Status assigned to this application.");
        }
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping("{appId}/objects")
    public @ResponseBody Object getBaseObjects(@PathVariable("appId") Integer appId) throws IOException {
        Map<String, Object> map = new HashMap<>();

        Application application = applicationService.loadApplication(appId);

        applicationService.decryptRepositoryCredentials(application);

        // manual Finding form
        map.put("manualSeverities", findingService.getManualSeverities());
        map.put("recentPathList", findingService.getRecentDynamicPaths(appId));
        map.put("recentFileList", findingService.getRecentStaticPaths(appId));
        map.put("manualChannelVulnerabilities", genericVulnerabilityService.loadAll());

        // defect tracker add form
        map.put("defectTrackerList", defectTrackerService.loadAllDefectTrackers());
        map.put("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());

        // waf
        map.put("wafList", wafService.loadAll());
        map.put("wafTypeList", wafService.loadAllWafTypes());

        // basic information
        map.put("application", application);

        if (policyStatusService != null) {
            map.put("passFilters", policyStatusService.passFilters(application));
        }

        // scans tab
        map.put("scans", checkDownloadable(application.getScans()));

        // doc tab
        map.put("documents", application.getDocuments());

        // scan agent tasks tab
        map.put("scanAgentTasks", application.getScanQueueTasks());

        // scheduled scan tab
        map.put("scheduledScans", application.getScheduledScans());

        // versions
        map.put("versions", application.getVersions());

        // edit form
        map.put("applicationTypes", FrameworkType.values());
        map.put("applicationCriticalityList", applicationCriticalityService.loadAll());
        map.put("teams", organizationService.loadTeams(Permission.CAN_MANAGE_TEAMS, false));

        // tagging
        map.put("tags", tagService.loadAllApplicationTags());
        map.put("applicationTags", application.getTags());
        map.put("isEnterprise", EnterpriseTest.isEnterprise());

        if (EnterpriseTest.isEnterprise()) {
            map.put("policies", applicationService.loadUnassociatedPolicies(application));
            map.put("scanAgentSupportedList", ScannerType.getScanAgentSupportedListInString());
            map.put("policyExist", policyService.loadAll().size() > 0);
        }

        // permissions
        for (Permission permission : new Permission[]{Permission.CAN_MANAGE_DEFECT_TRACKERS, Permission.CAN_MANAGE_WAFS}) {
            map.put(permission.getCamelCase(), PermissionUtils.hasGlobalPermission(permission));
        }

        return success(map);
    }

    private List<Scan> checkDownloadable(List<Scan> scans) {
        if (scans != null) {
            DefaultConfiguration defaultConfiguration = defaultConfigService.loadCurrentConfiguration();

            for (Scan scan: scans) {
                scan.setDownloadable(defaultConfiguration.fileUploadLocationExists()
                        && DiskUtils.isFileExists(defaultConfiguration.getFullFilePath(scan)));
            }

        }
        return scans;
    }

    private String getActiveTab(HttpServletRequest request, long falsePositiveCount, long numClosedVulns) {
        String activeTab = ControllerUtils.getActiveTab(request);
        if (activeTab != null) {
            if (activeTab.equals(ControllerUtils.FALSE_POSITIVE_TAB) && falsePositiveCount == 0)
                return null;
            if (activeTab.equals(ControllerUtils.CLOSED_VULN_TAB) && numClosedVulns == 0)
                return null;
        }

        return activeTab;
    }

    private void addAttrForScheduledScanTab(Model model) {
        List<String> scannerTypeList = list();
        List<ChannelType> channelTypeList = channelTypeService.getChannelTypeOptions(null);
        for (ChannelType type: channelTypeList) {
            scannerTypeList.add(type.getName());
        }

        Collections.sort(scannerTypeList);
        model.addAttribute("scannerTypeList", scannerTypeList);
        model.addAttribute("scheduledScan", new ScheduledScan());
        model.addAttribute("frequencyTypes", ScheduledFrequencyType.values());
        model.addAttribute("periodTypes", ScheduledPeriodType.values());
        model.addAttribute("scheduledDays", DayInWeek.values());
    }

	// TODO move this to a different spot so as to be less annoying
	private Map<String, Object> addDefectModelAttributes(int appId, int orgId, boolean addDefectIds) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_SUBMIT_DEFECTS, orgId, appId)) {
			return null;
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		if (application.getDefectTracker() == null ||
				application.getDefectTracker().getDefectTrackerType() == null) {
			return null;
		}

		applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		ProjectMetadata data = null;

        List<Defect> defectList = null;
        Map<String, Object> map = new HashMap<>();

		if (dt != null) {
            if (addDefectIds) {
                defectList = dt.getDefectList();
                if (dt.getLastError() != null && !dt.getLastError().isEmpty()) {
                    map.put(ERROR_MSG, dt.getLastError());
                    return map;
                }
            } else {
                defectList = list();
            }

			data = defectTrackerService.getProjectMetadata(dt);
            if (dt.getLastError() != null && !dt.getLastError().isEmpty()) {
                map.put(ERROR_MSG, dt.getLastError());
                return map;
            }
		}

		map.put("defectTrackerName", application.getDefectTracker().getDefectTrackerType().getName());
		map.put("defectList", getNativeIds(defectList));
		map.put("projectMetadata", data);

		return map;
	}

    // TODO return a list of strings directly from the defect tracker integrations instead of unboxing them here
    // They have a relatively small memory cost but I don't see any advantages at this point
    private List<String> getNativeIds(List<Defect> defectList) {
        List<String> nativeIds = list();

        for (Defect defect : defectList) {
            nativeIds.add(defect.getNativeId());
        }

        return nativeIds;
    }

    @RequestMapping("/{appId}/defectSubmission")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionForm(
            @PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		Map<String, Object> returnMap = addDefectModelAttributes(appId, orgId, false);

        if (returnMap.get(ERROR_MSG) != null) {
            return failure(returnMap.get(ERROR_MSG).toString());
        } else {
            return success(returnMap);
        }
	}

	@RequestMapping("/{appId}/defectSubmissionWithIssues")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionWithIssues(
            @PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		Map<String, Object> returnMap = addDefectModelAttributes(appId, orgId, true);

        if (returnMap.get(ERROR_MSG) != null) {
            return failure(returnMap.get(ERROR_MSG).toString());
        } else {
            return success(returnMap);
        }
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_APPLICATIONS')")
	@RequestMapping("/{appId}/delete")
	public String processLinkDelete(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, SessionStatus status) {
		
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application != null && application.isActive()) {
			applicationService.deactivateApplication(application);
			status.setComplete();
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		return "redirect:/organizations/" + String.valueOf(orgId);
	}

	// TODO move this elsewhere?
	@RequestMapping(value = "/jsontest", method = RequestMethod.POST)
	public @ResponseBody RestResponse<?> readJson(@ModelAttribute DefectTrackerBean bean) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(bean
				.getDefectTrackerId());

        String username = bean.isUseDefaultCredentials() ? defectTracker.getDefaultUsername() : bean.getUserName();
        String password = bean.isUseDefaultCredentials() ? defectTracker.getDefaultPassword() : bean.getPassword();

		AbstractDefectTracker dt = DefectTrackerFactory.getTrackerByType(defectTracker, username, password);

		if (dt == null) {
			log.warn("Incorrect Defect Tracker credentials submitted.");
			return failure("Authentication failed.");
		}
		List<String> result = dt.getProductNames();
		if (result.isEmpty() || (result.size() == 1 && result.contains("Authentication failed"))) {
			return failure(JSONObject.quote(dt.getLastError()));
		}

        // ensure there are no duplicates. There's probably a better idiom
        result = listFrom(setFrom(result));

        Collections.sort(result);

		return success(result);
	}

    @RequestMapping(value = "/{appId}/unmappedTable", method = RequestMethod.POST)
    @JsonView(AllViews.TableRow.class)
    public @ResponseBody Object unmappedScanTable(@ModelAttribute TableSortBean bean,
                                                  @PathVariable("appId") Integer appId,
                                                  @PathVariable("orgId") Integer orgId) throws IOException {

        if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
            return "403";
        }

        long numFindings = applicationService.getUnmappedFindingCount(appId);

        if (bean.getPage() < 1) {
            bean.setPage(1);
        }

        bean.setApplicationId(appId);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("page", bean.getPage());
        responseMap.put("numFindings", numFindings);
        responseMap.put("findingList", findingService.getUnmappedFindingTable(bean));

        return success(responseMap);
    }

    @JsonView(AllViews.TableRow.class)
    @RequestMapping(value = "/{appId}/cwe", method = RequestMethod.GET)
    public @ResponseBody Object getGenericVulnerabilities() throws IOException {
        return success(genericVulnerabilityService.loadAll());
    }
}
