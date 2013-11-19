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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.enums.SourceCodeAccessLevel;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.UserService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.defects.ProjectMetadata;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.DefectViewModel;
import com.denimgroup.threadfix.webapp.viewmodels.ScanParametersBean;
import com.denimgroup.threadfix.webapp.viewmodels.VulnerabilityCollectionModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications")
@SessionAttributes({"defectTracker", "application", "waf", "defectViewModel", "scanParametersBean"})
public class ApplicationsController {
	
	public ApplicationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(ApplicationsController.class);

	private FindingService findingService;
	private ApplicationCriticalityService applicationCriticalityService;
	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private WafService wafService;
	private PermissionService permissionService;
	private OrganizationService organizationService;
	private UserService userService;
	private ChannelVulnerabilityService channelVulnerabilityService;

	@Autowired
	public ApplicationsController(ApplicationService applicationService,
			FindingService findingService,
			ApplicationCriticalityService applicationCriticalityService,
			WafService wafService,
			DefectTrackerService defectTrackerService,
			PermissionService permissionService,
			OrganizationService organizationService,
			UserService userService,
			ChannelVulnerabilityService channelVulnerabilityService) {
		this.wafService = wafService;
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.permissionService = permissionService;
		this.findingService = findingService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.organizationService = organizationService;
		this.userService = userService;
		this.channelVulnerabilityService = channelVulnerabilityService;
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@RequestMapping("/{appId}")
	public String detail(@PathVariable("orgId") Integer orgId, @PathVariable("appId") Integer appId,
			Model model, HttpServletRequest request) {
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		Object successMessage = ControllerUtils.getSuccessMessage(request);
		Object error = ControllerUtils.getErrorMessage(request);

		TableSortBean falsePositiveBean = new TableSortBean();
		falsePositiveBean.setFalsePositive(true);
		
		long numVulns = applicationService.getVulnCount(appId, true);
		long numClosedVulns = applicationService.getVulnCount(appId, false);
		long falsePositiveCount = applicationService.getCount(appId, falsePositiveBean);
		
		TableSortBean hiddenBean = new TableSortBean();
		hiddenBean.setHidden(true);
		
		long numHiddenVulns = applicationService.getCount(appId, hiddenBean);
		
		permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS,
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
		
		Object checkForRefresh = ControllerUtils.getItem(request, "checkForRefresh");
		Object numScansBeforeUpload = ControllerUtils.getItem(request, "numScansBeforeUpload");
		model.addAttribute("numScansBeforeUpload", numScansBeforeUpload);
		model.addAttribute("checkForRefresh", checkForRefresh);
		model.addAttribute("applicationCriticalityList", applicationCriticalityService.loadAll());
		model.addAttribute("manualSeverities", findingService.getManualSeverities());
		model.addAttribute("urlManualList", findingService.getAllManualUrls(appId));
		model.addAttribute("numVulns", numVulns);
		model.addAttribute("defectTrackerList", defectTrackerService.loadAllDefectTrackers());
		model.addAttribute("defectTrackerTypeList", defectTrackerService.loadAllDefectTrackerTypes());
		model.addAttribute("defectTracker", new DefectTracker());
		model.addAttribute("waf", new Waf());
		model.addAttribute("createWafUrl", "wafs/new/ajax/appPage");
		model.addAttribute("newWaf", new Waf());
		model.addAttribute("wafList", wafService.loadAll());
		model.addAttribute("wafTypeList", wafService.loadAllWafTypes());
		model.addAttribute("numClosedVulns", numClosedVulns);
		model.addAttribute(new VulnerabilityCollectionModel());
		model.addAttribute("successMessage", successMessage);
		model.addAttribute("errorMessage", error);
		model.addAttribute(application);
		model.addAttribute("falsePositiveCount", falsePositiveCount);
		model.addAttribute("numHiddenVulns", numHiddenVulns);
		model.addAttribute("finding", new Finding());
		model.addAttribute(new DefectViewModel());
		model.addAttribute("scanParametersBean", ScanParametersBean.getScanParametersBean(application));
		model.addAttribute("applicationTypes", FrameworkType.values());
		model.addAttribute("sourceCodeAccessLevels", SourceCodeAccessLevel.values());
		model.addAttribute("teamList", organizationService.loadAllActive());
		if (permissionService.isAuthorized(Permission.CAN_MANAGE_USERS,orgId,appId)) {
			model.addAttribute("users", userService.getPermissibleUsers(orgId, appId));
		}
		model.addAttribute("manualChannelVulnerabilities", channelVulnerabilityService.loadAllManual());
		return "applications/detail";
	}
	
	// TODO move this to a different spot so as to be less annoying
	private void addDefectModelAttributes(Model model, int appId, int orgId) {
		if (!permissionService.isAuthorized(Permission.CAN_SUBMIT_DEFECTS, orgId, appId)) {
			return;
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		if (application.getDefectTracker() == null ||
				application.getDefectTracker().getDefectTrackerType() == null) {
			return;
		}
		
		applicationService.decryptCredentials(application);

		AbstractDefectTracker dt = DefectTrackerFactory.getTracker(application);
		ProjectMetadata data = null;

		if (dt != null) {
			data = dt.getProjectMetadata();
		}
		
		model.addAttribute("defectTrackerName",
				application.getDefectTracker().getDefectTrackerType().getName());
		model.addAttribute("projectMetadata", data);
		model.addAttribute(new DefectViewModel());
	}
	
	@RequestMapping("/{appId}/defectSubmission")
	public String getDefectSubmissionForm(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, SessionStatus status, Model model) {
		
		addDefectModelAttributes(model, appId, orgId);
		
		model.addAttribute("contentPage", "defects/submitDefectForm.jsp");
		
		return "ajaxSuccessHarness";
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_APPLICATIONS')")
	@RequestMapping("/{appId}/delete")
	public String processLinkDelete(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, SessionStatus status) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
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
	public @ResponseBody String readJson(@RequestBody DefectTrackerBean bean) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(bean
				.getDefectTrackerId());
		AbstractDefectTracker dt = DefectTrackerFactory.getTrackerByType(defectTracker,
				bean.getUserName(), bean.getPassword());
		if (dt == null) {
			log.warn("Incorrect Defect Tracker credentials submitted.");
			return "Authentication failed";
		}
		String result = dt.getProductNames();
		if (result == null || result.equals("Authentication failed")) {
			return "{ \"message\" : \"Authentication failed\", " +
					"\"error\" : " + JSONObject.quote(dt.getLastError())  + "}";
		}

		return "{ \"message\" : \"Authentication success\", " +
				"\"names\" : " + JSONObject.quote(productSort(result))  + "}";
	}
	
	private String productSort(String products) {
		if (products == null) {
			return "Authentication failed";
		}
		String[] splitArray = products.split(",", 0);
		
		if (splitArray.length == 0) {
			return "Authentication failed";
		}
		
		Arrays.sort(splitArray, String.CASE_INSENSITIVE_ORDER);
		StringBuilder result = new StringBuilder();
		
		for (String product : splitArray) {
			if (product != null && !product.trim().equals("")) {
				result.append(',').append(product);
			}
		}
		
		return result.substring(1);
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
