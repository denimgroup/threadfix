////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2012 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.webapp.controller;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.denimgroup.threadfix.webapp.viewmodels.FalsePositiveModel;

@Controller
@RequestMapping("/organizations/{orgId}/applications")
public class ApplicationsController {
	
	public ApplicationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(ApplicationsController.class);

	private ApplicationService applicationService;
	private DefectTrackerService defectTrackerService;
	private VulnerabilityService vulnerabilityService;
	private PermissionService permissionService;

	@Autowired
	public ApplicationsController(ApplicationService applicationService,
			DefectTrackerService defectTrackerService,
			PermissionService permissionService,
			VulnerabilityService vulnerabilityService) {
		this.applicationService = applicationService;
		this.defectTrackerService = defectTrackerService;
		this.permissionService = permissionService;
		this.vulnerabilityService = vulnerabilityService;
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

		Object message = getAttribute(request, "scanSuccessMessage");
		Object error = getAttribute(request, "scanErrorMessage");
		if (message == null) {
			message = getAttribute(request, "queueSuccessMessage");
		}

		TableSortBean falsePositiveBean = new  TableSortBean();
		falsePositiveBean.setFalsePositive(true);
		
		long numVulns = applicationService.getVulnCount(appId, true);
		long numClosedVulns = applicationService.getVulnCount(appId, false);
		long falsePositiveCount = applicationService.getCount(appId, falsePositiveBean);
		
		
		permissionService.addPermissions(model, orgId, appId, Permission.CAN_MANAGE_APPLICATIONS, 
				Permission.CAN_UPLOAD_SCANS, Permission.CAN_MODIFY_VULNERABILITIES, 
				Permission.CAN_SUBMIT_DEFECTS, Permission.CAN_VIEW_JOB_STATUSES );
		
		model.addAttribute("numVulns", numVulns);
		model.addAttribute("numClosedVulns", numClosedVulns);
		model.addAttribute(new FalsePositiveModel());
		model.addAttribute("message", message);
		model.addAttribute("error", error);
		model.addAttribute(application);
		model.addAttribute("falsePositiveCount", falsePositiveCount);
		return "applications/detail";
	}
	
	private Object getAttribute(HttpServletRequest request, String attribute) {
		Object returnValue = null;
		if (request.getSession() != null) {
			returnValue = request.getSession().getAttribute(attribute);
			if (returnValue != null) {
				request.getSession().removeAttribute(attribute);
			}
		}
		
		return returnValue;
	}
	
	@RequestMapping("/{appId}/closedVulnerabilities")
	public String viewClosedVulnerabilities(@PathVariable("orgId") int orgId, 
			@PathVariable("appId") int appId, ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}

		TableSortBean basicBean = new TableSortBean();
		basicBean.setOpen(false);
		long numVulns = applicationService.getCount(appId, basicBean);
		
		model.addAttribute("numVulns", numVulns);
		model.addAttribute(application);
		return "applications/closedVulns";
	}
	
	@RequestMapping(value="/{appId}/closedVulnerabilities/table", method = RequestMethod.POST)
	public String getClosedTableVulns(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@RequestBody TableSortBean bean,
			ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		bean.setOpen(false);
		bean.setFalsePositive(false);
		
		long numVulns = applicationService.getCount(appId, bean);
		long numPages = (numVulns / 100);
		if (numVulns % 100 == 0) {
			numPages -= 1;
		}
		model.addAttribute("numPages", numPages);
		model.addAttribute("numVulns", numVulns);
		
		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
		
		model.addAttribute("page", bean.getPage());
		model.addAttribute("vulnerabilities", applicationService.getVulnTable(appId, bean));
		model.addAttribute(application);
		return "applications/closedTable";
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
	
	@RequestMapping(value="/{appId}/table", method = RequestMethod.POST)
	public String getTableVulns(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@RequestBody TableSortBean bean,
			Model model) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		bean.setOpen(true);
		bean.setFalsePositive(false);
		
		long numVulns = applicationService.getCount(appId, bean);
		long numPages = (numVulns / 100);
		if (numVulns % 100 == 0) {
			numPages -= 1;
		}
		model.addAttribute("numPages", numPages);
		model.addAttribute("numVulns", numVulns);
		
		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
		
		List<Vulnerability> vulnList = applicationService.getVulnTable(appId, bean);
		
		model.addAttribute("ages", vulnerabilityService.getAges(vulnList));
		model.addAttribute("page", bean.getPage());
		model.addAttribute("vulnerabilities", vulnList);
		model.addAttribute(application);
		permissionService.addPermissions(model, orgId, appId, Permission.CAN_MODIFY_VULNERABILITIES);
		return "applications/vulnTable";
	}
	
	@RequestMapping(value="/{appId}/defectTable", method = RequestMethod.POST)
	public String getDefectTableVulns(@PathVariable("orgId") Integer orgId,
			@PathVariable("appId") Integer appId,
			@RequestBody TableSortBean bean,
			ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null || !application.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		bean.setOpen(true);
		bean.setFalsePositive(false);
		
		long numVulns = applicationService.getCount(appId, bean);
		long numPages = (numVulns / 100);
		if (numVulns % 100 == 0) {
			numPages -= 1;
		}
		model.addAttribute("numPages", numPages);
		model.addAttribute("numVulns", numVulns);
		
		if (bean.getPage() > numPages) {
			bean.setPage((int) (numPages + 1));
		}
		
		if (bean.getPage() < 1) {
			bean.setPage(1);
		}
		
		model.addAttribute("page", bean.getPage());
		model.addAttribute("vulnerabilities", applicationService.getVulnTable(appId, bean));
		model.addAttribute(application);
		return "defects/defectVulnTable";
	}
}
