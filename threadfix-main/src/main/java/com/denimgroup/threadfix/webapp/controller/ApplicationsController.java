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
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.DefectTrackerBean;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.ProjectMetadata;
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

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.*;

@Controller
@RequestMapping("/organizations/{orgId}/applications")
@SessionAttributes({"defectTracker", "application", "waf", "defectViewModel", "scanParametersBean"})
public class ApplicationsController {
	
	public ApplicationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(ApplicationsController.class);

    @Autowired
	private FindingService findingService;
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
				Permission.CAN_SUBMIT_DEFECTS,
				Permission.CAN_VIEW_JOB_STATUSES,
				Permission.CAN_GENERATE_REPORTS,
				Permission.CAN_MANAGE_DEFECT_TRACKERS,
				Permission.CAN_MANAGE_USERS);
		
		if (application.getPassword() != null && !"".equals(application.getPassword())) {
			application.setPassword(Application.TEMP_PASSWORD);
		}

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

    /**
     *
     * @return objects in JSON format needed on the applications page.
     */
    @RequestMapping("{appId}/objects")
    public @ResponseBody String getObjects(@PathVariable("appId") Integer appId) throws IOException {
        Map<String, Object> map = new HashMap<>();

        Application application = applicationService.loadApplication(appId);

        map.put("application", application);
        map.put("defectTrackerList", defectTrackerService.loadAllDefectTrackers());
        map.put("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());
        map.put("wafList", wafService.loadAll());
        map.put("wafTypeList", wafService.loadAllWafTypes());
        map.put("applicationTypes", FrameworkType.values());
        map.put("applicationCriticalityList", applicationCriticalityService.loadAll());
        map.put("teams", organizationService.loadAllActive());
        map.put("scans", application.getScans());

        String data = getWriter().writeValueAsString(RestResponse.success(map));

        return data;
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
        List<String> scannerTypeList = new ArrayList<>();
        List<ChannelType> channelTypeList = channelTypeService.getChannelTypeOptions(null);
        for (ChannelType type: channelTypeList) {
            scannerTypeList.add(type.getName());
        }

        Collections.sort(scannerTypeList);
        model.addAttribute("scannerTypeList", scannerTypeList);
        model.addAttribute("scheduledScan", new ScheduledScan());
        model.addAttribute("frequencyTypes", ScheduledScan.ScheduledFrequencyType.values());
        model.addAttribute("periodTypes", ScheduledScan.ScheduledPeriodType.values());
        model.addAttribute("scheduledDays", ScheduledScan.DayInWeek.values());
    }
	
	// TODO move this to a different spot so as to be less annoying
	private Map<String, Object> addDefectModelAttributes(int appId, int orgId) {
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
		if (dt != null) {
            defectList = dt.getDefectList();
			data = dt.getProjectMetadata();
		}

        Map<String, Object> map = new HashMap<>();

		map.put("defectTrackerName", application.getDefectTracker().getDefectTrackerType().getName());
		map.put("defectList", defectList);
		map.put("projectMetadata", data);

		return map;
	}

	@RequestMapping("/{appId}/defectSubmission")
	public @ResponseBody RestResponse<Map<String, Object>> getDefectSubmissionForm(
            @PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {

		Map<String, Object> returnMap = addDefectModelAttributes(appId, orgId);

        if (returnMap == null) {
            return RestResponse.failure("Unable to retrieve Defect Tracker information.");
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
	public @ResponseBody RestResponse<? extends Object> readJson(@ModelAttribute DefectTrackerBean bean) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(bean
				.getDefectTrackerId());
		AbstractDefectTracker dt = DefectTrackerFactory.getTrackerByType(defectTracker,
				bean.getUserName(), bean.getPassword());
		if (dt == null) {
			log.warn("Incorrect Defect Tracker credentials submitted.");
			return RestResponse.failure("Authentication failed.");
		}
		String result = dt.getProductNames();
		if (result == null || result.equals("Authentication failed")) {
			return RestResponse.failure(JSONObject.quote(dt.getLastError()));
		}

		return RestResponse.success(productSort(result));
	}
	
	private String[] productSort(String products) {
		if (products == null) {
			return null;
		}
		String[] splitArray = products.split(",", 0);
		
		if (splitArray.length == 0) {
			return null;
		}
		
		Arrays.sort(splitArray, String.CASE_INSENSITIVE_ORDER);

		return splitArray;
	}
	
	@RequestMapping("/{appId}/getDefectsFromDefectTracker")
	public String getDefectsFromDefectTracker(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, SessionStatus status, Model model) {
		
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
		List<Defect> defectList = new ArrayList<>();
		
		ProjectMetadata data = null;
		if (dt != null) {
			data = dt.getProjectMetadata();
			defectList = dt.getDefectList();
		}
		model.addAttribute("projectMetadata", data);
		model.addAttribute("defectList", defectList);
		model.addAttribute(new DefectViewModel());
		model.addAttribute("contentPage", "defects/mergeDefectForm.jsp");
		
		log.info("Ended getting defect list.");
		
		return "ajaxSuccessHarness";
	}

}
