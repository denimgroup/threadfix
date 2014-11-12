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

import com.denimgroup.threadfix.data.dao.ActivityFeedDao;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.ActivityFeedTypeName;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.DefectTrackerBean;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import com.denimgroup.threadfix.service.defects.VersionOneDefectTracker;
import com.denimgroup.threadfix.viewmodel.DynamicFormField;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;
import com.denimgroup.threadfix.webapp.viewmodels.VulnerabilityCollectionModel;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.ObjectWriter;
import org.codehaus.jackson.map.SerializationConfig;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.service.util.ControllerUtils.writeSuccessObjectWithView;

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
    private ActivityFeedDao activityFeedDao;
    @Autowired
    private TagService tagService;

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
//				Permission.CAN_VIEW_JOB_STATUSES,
				Permission.CAN_GENERATE_REPORTS,
				Permission.CAN_MANAGE_DEFECT_TRACKERS,
				Permission.CAN_MANAGE_USERS,
                Permission.CAN_MANAGE_TAGS);
		
		if (application.getPassword() != null && !"".equals(application.getPassword())) {
			application.setPassword(Application.TEMP_PASSWORD);
		}

        model.addAttribute("tagList", application.getTags());
		model.addAttribute("urlManualList", findingService.getAllManualUrls(appId));
		model.addAttribute("numVulns", numVulns);
		model.addAttribute("defectTracker", new DefectTracker());
		model.addAttribute("waf", new Waf());
		model.addAttribute("newWaf", new Waf());
		model.addAttribute(new VulnerabilityCollectionModel());
        model.addAttribute("activeTab", getActiveTab(request, falsePositiveCount, numClosedVulns));
		model.addAttribute(application);
		model.addAttribute("finding", new Finding());
		model.addAttribute(new DefectViewModel());
        model.addAttribute("isEnterprise", EnterpriseTest.isEnterprise());
		if (PermissionUtils.isAuthorized(Permission.CAN_MANAGE_USERS,orgId,appId)) {
			model.addAttribute("users", userService.getPermissibleUsers(orgId, appId));
		}
		model.addAttribute("manualChannelVulnerabilities", channelVulnerabilityService.loadAllManual());
        addAttrForScheduledScanTab(model);
		return "applications/detail";
	}

    private ObjectWriter getWriter() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(SerializationConfig.Feature.DEFAULT_VIEW_INCLUSION, false);

        return mapper.writerWithView(AllViews.FormInfo.class);
    }

    @RequestMapping("{appId}/objects")
    public @ResponseBody String getBaseObjects(@PathVariable("appId") Integer appId) throws IOException {
        Map<String, Object> map = new HashMap<>();

        Application application = applicationService.loadApplication(appId);

        applicationService.decryptRepositoryCredentials(application);

        // manual Finding form
        map.put("manualSeverities", findingService.getManualSeverities());
        map.put("recentPathList", findingService.getRecentDynamicPaths(appId));
        map.put("recentFileList", findingService.getRecentStaticPaths(appId));
        map.put("manualChannelVulnerabilities", channelVulnerabilityService.loadAllManual());

        // defect tracker add form
        map.put("defectTrackerList", defectTrackerService.loadAllDefectTrackers());
        map.put("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());

        map.put("wafList", wafService.loadAll());
        map.put("wafTypeList", wafService.loadAllWafTypes());

        // basic information
        map.put("application", application);

        // scans tab
        map.put("scans", application.getScans());

        // activity feed
        map.put("feed", activityFeedDao.retrieveByTypeAndObjectId(ActivityFeedTypeName.APPLICATION, appId));

        // doc tab
        map.put("documents", application.getDocuments());

        // scan agent tasks tab
        map.put("scanAgentTasks", application.getScanQueueTasks());

        // scheduled scan tab
        map.put("scheduledScans", application.getScheduledScans());

        // edit form
        map.put("applicationTypes", FrameworkType.values());
        map.put("applicationCriticalityList", applicationCriticalityService.loadAll());
        map.put("teams", organizationService.loadAllActive());

        // tagging
        map.put("tags", tagService.loadAll());

        map.put("applicationTags", application.getTags());

        return getSerializedMap(map);
    }

    private String getSerializedMap(Map<String, Object> map) throws IOException {
        return getWriter().writeValueAsString(RestResponse.success(map));
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

    private void addAdditionalScannerInfoField(@Nonnull List<DynamicFormField> formFields){
        DynamicFormField additionalScannerInfoField = new DynamicFormField();
        additionalScannerInfoField.setName("AdditionalScannerInfo");
        additionalScannerInfoField.setLabel("Additional Scanner Info");
        additionalScannerInfoField.setRequired(false);
        additionalScannerInfoField.setType("checkbox");
        additionalScannerInfoField.setActive(true);
        additionalScannerInfoField.setEditable(true);
        additionalScannerInfoField.setSupportsMultivalue(false);

        formFields.add(additionalScannerInfoField);
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

            // adding additional scanner info checkbox, checking for null dynamicformfields
            List<DynamicFormField> editableFields = data.getEditableFields();

            if (editableFields != null) {
                addAdditionalScannerInfoField(editableFields);

                //remove Order field in Version One dynamic form
                if (dt.getClass().equals(VersionOneDefectTracker.class)) {
                    DynamicFormField orderField = null;
                    for (DynamicFormField field : editableFields) {
                        if (field.getName().equals("Order")) {
                            orderField = field;
                        }
                    }

                    if (orderField != null) {
                        editableFields.remove(orderField);
                    }
                }
            }
		}

		map.put("defectTrackerName", application.getDefectTracker().getDefectTrackerType().getName());
		map.put("defectList", defectList);
		map.put("projectMetadata", data);

		return map;
	}

	@RequestMapping("/{appId}/defectSubmission")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionForm(
            @PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		Map<String, Object> returnMap = addDefectModelAttributes(appId, orgId, false);

        if (returnMap.get(ERROR_MSG) != null) {
            return RestResponse.failure(returnMap.get(ERROR_MSG).toString());
        } else {
            return RestResponse.success(returnMap);
        }
	}

	@RequestMapping("/{appId}/defectSubmissionWithIssues")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionWithIssues(
            @PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		Map<String, Object> returnMap = addDefectModelAttributes(appId, orgId, true);

        if (returnMap.get(ERROR_MSG) != null) {
            return RestResponse.failure(returnMap.get(ERROR_MSG).toString());
        } else {
            return RestResponse.success(returnMap);
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
		AbstractDefectTracker dt = DefectTrackerFactory.getTrackerByType(defectTracker,
				bean.getUserName(), bean.getPassword());
		if (dt == null) {
			log.warn("Incorrect Defect Tracker credentials submitted.");
			return RestResponse.failure("Authentication failed.");
		}
		List<String> result = dt.getProductNames();
		if (result.isEmpty() || (result.size() == 1 && result.contains("Authentication failed"))) {
			return RestResponse.failure(JSONObject.quote(dt.getLastError()));
		}

        // ensure there are no duplicates. There's probably a better idiom
        result = listFrom(setFrom(result));

        Collections.sort(result);

		return RestResponse.success(result);
	}
	
	@RequestMapping("/{appId}/getDefectsFromDefectTracker")
	public String getDefectsFromDefectTracker(@PathVariable("appId") int appId, Model model) {
		
		log.info("Start getting defect list.");
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		if (application.getDefectTracker() == null ||
				application.getDefectTracker().getDefectTrackerType() == null) {
			return "";
		}
		applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		List<Defect> defectList = list();
		
		ProjectMetadata data = null;
		if (dt != null) {
			data = defectTrackerService.getProjectMetadata(dt);
			defectList = dt.getDefectList();
		}
		model.addAttribute("projectMetadata", data);
		model.addAttribute("defectList", defectList);
		model.addAttribute(new DefectViewModel());
		model.addAttribute("contentPage", "defects/mergeDefectForm.jsp");
		
		log.info("Ended getting defect list.");
		
		return "ajaxSuccessHarness";
	}

    @RequestMapping(value = "/{appId}/unmappedTable", method = RequestMethod.POST)
    public @ResponseBody String unmappedScanTable(@ModelAttribute TableSortBean bean,
                                                  @PathVariable("appId") Integer appId,
                                                  @PathVariable("orgId") Integer orgId) throws IOException {

        if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS,orgId,appId)) {
            return "403";
        }

        long numFindings = applicationService.getUnmappedFindingCount(appId);
        long numPages = numFindings / 100;

        if (numFindings % 100 == 0) {
            numPages -= 1;
        }

        if (bean.getPage() >= numPages) {
            bean.setPage((int) (numPages + 1));
        }

        if (bean.getPage() < 1) {
            bean.setPage(1);
        }

        bean.setApplicationId(appId);

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("numPages", numPages);
        responseMap.put("page", bean.getPage());
        responseMap.put("numFindings", numFindings);
        responseMap.put("findingList", findingService.getUnmappedFindingTable(bean));

        return writeSuccessObjectWithView(responseMap, AllViews.TableRow.class);
    }

    @RequestMapping(value = "/{appId}/cwe", method = RequestMethod.GET)
    public @ResponseBody Object getGenericVulnerabilities() throws IOException {
        return writeSuccessObjectWithView(
                genericVulnerabilityService.loadAll(),
                AllViews.TableRow.class);
    }
}
