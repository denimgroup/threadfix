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

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanMergeService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/new")
@SessionAttributes("application")
public class AddFindingController {
	
	protected final SanitizedLogger log = new SanitizedLogger(AddFindingController.class);

	private ApplicationService applicationService;
	private PermissionService permissionService;
	private ScanMergeService scanMergeService;
	private ChannelVulnerabilityService channelVulnerabilityService;
	private FindingService findingService;

	@Autowired
	public AddFindingController(ApplicationService applicationService,
			ScanMergeService scanMergeService,
			ChannelVulnerabilityService channelVulnerabilityService,
			FindingService findingService,
			PermissionService organizationService) {
		this.applicationService = applicationService;
		this.scanMergeService = scanMergeService;
		this.permissionService = organizationService;
		this.channelVulnerabilityService = channelVulnerabilityService;
		this.findingService = findingService;
	}

	@ModelAttribute
	public List<ChannelSeverity> populateChannelSeverity() {
		return findingService.getManualSeverities();
	}
	
	@ModelAttribute("staticChannelVulnerabilityList")
	public List<String> populateStaticChannelVulnerablility(@PathVariable("appId") int appId){
		return findingService.getRecentStaticVulnTypes(appId);
	}
	
	@ModelAttribute("dynamicChannelVulnerabilityList")
	public List<String> populateDynamicChannelVulnerablility(@PathVariable("appId") int appId){
		return findingService.getRecentDynamicVulnTypes(appId);
	}
	
	@ModelAttribute("staticPathList")
	public List<String> populateStaticPath(@PathVariable("appId") int appId) {
		return findingService.getRecentStaticPaths(appId);
	}
	
	@ModelAttribute("dynamicPathList")
	public List<String> populateDynamicPath(@PathVariable("appId") int appId) {
		return findingService.getRecentDynamicPaths(appId);
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView addNewFinding(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return new ModelAndView("403");
		}
		
		Application application = applicationService.loadApplication(appId);
		if (application == null)
			return new ModelAndView("redirect:/organizations/" + orgId);
			
		ModelAndView mav = new ModelAndView("scans/form");
		mav.addObject(new Finding());
		mav.addObject(application);
		return mav;
	}

	@RequestMapping(params = "group=static", method = RequestMethod.POST)
	public String staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
		
		if (result.hasErrors()) {
			model.addAttribute("isStatic",true);
			return "scans/form";
			
		} else {
			finding.setIsStatic(true);
			boolean mergeResult = scanMergeService.processManualFinding(finding, appId);
			
			if (!mergeResult) {
				log.warn("The merge failed. Returning the form again.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("static",true);
				return "scans/form";
			} else {
				status.setComplete();
				return "redirect:/organizations/" + orgId + "/applications/" + appId;
			}
		}
	}
	
	@RequestMapping(params = "group=dynamic", method = RequestMethod.POST)
	public String dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, ModelMap model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
		
		if (result.hasErrors()) {
			model.addAttribute("isStatic",false);
			return "scans/form";
		} else {
			finding.setIsStatic(false);
			boolean mergeResult = scanMergeService.processManualFinding(finding, appId);
			
			if (!mergeResult) {
				log.warn("The merge failed. Returning the form again.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("static",false);
				return "scans/form";
			} else {
				status.setComplete();
				return "redirect:/organizations/" + orgId + "/applications/" + appId;
			}
		}
	}

	@RequestMapping(value = "/ajax_cwe", method = RequestMethod.POST)
	@ResponseBody
	public String readAjaxCWE(@RequestParam String prefix) {
		if (prefix == null || prefix.equals(""))
			return "";
		List<ChannelVulnerability> cVulnList = channelVulnerabilityService.loadSuggested(prefix);
		if (cVulnList == null)
			return "";

		StringBuffer buffer = new StringBuffer();
		for (ChannelVulnerability gVuln : cVulnList) {
			if (gVuln == null || gVuln.getName() == null || gVuln.getName().trim().equals(""))
				continue;
			buffer.append(gVuln.getName()).append('\n');
		}
		return buffer.toString();
	}

	@RequestMapping(value = "/ajax_url", method = RequestMethod.POST)
	@ResponseBody
	public String readAjaxURL(@RequestParam String hint,
			@PathVariable("appId") int appId) {
		List<String> sourceFileList = findingService.loadSuggested(hint, appId);
		if (sourceFileList == null || sourceFileList.size() == 0)
			return "";

		StringBuffer buffer = new StringBuffer();
		for (String sourceFile : sourceFileList) {
			if (sourceFile == null || sourceFile.equals(""))
				continue;
			buffer.append(sourceFile).append('\n');
		}
		return buffer.toString();
	}

}
