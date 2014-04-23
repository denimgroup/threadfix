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
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ManualFindingService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/new")
@SessionAttributes("application")
public class AddFindingController {
	
	protected final SanitizedLogger log = new SanitizedLogger(AddFindingController.class);

    @Autowired
	private ApplicationService applicationService;
    @Autowired
	private ManualFindingService manualFindingService;
    @Autowired
	private ChannelVulnerabilityService channelVulnerabilityService;
    @Autowired
	private FindingService findingService;

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
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
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
	
	private String returnForm(ModelMap model, int appId) {
		model.addAttribute("contentPage", "applications/forms/manualFindingForm.jsp");
		model.addAttribute("application", applicationService.loadApplication(appId));
		model.addAttribute("manualSeverities", findingService.getManualSeverities());
		model.addAttribute("urlManualList", findingService.getAllManualUrls(appId));
		model.addAttribute("manualChannelVulnerabilities", channelVulnerabilityService.loadAllManual());
		return "ajaxFailureHarness";
	}

	@RequestMapping(params = "group=static", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status) {
	    return submitBackend(appId, orgId, finding, result, status, true);
	}
	
	@RequestMapping(params = "group=dynamic", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status) {
        return submitBackend(appId, orgId, finding, result, status, false);
    }

    private RestResponse<String> submitBackend(int appId, int orgId, Finding finding, BindingResult result, SessionStatus status, boolean isStatic) {
        if (!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
            return RestResponse.failure("You don't have permission to upload scans.");
        }

        findingService.validateManualFinding(finding, result);

        if (result.hasErrors()) {
            return FormRestResponse.failure("Form Validation failed.", result);

        } else {
            finding.setIsStatic(isStatic);
            boolean mergeResult = manualFindingService.processManualFinding(finding, appId);

            if (!mergeResult) {
                log.warn("The merge failed. Returning the form again.");
                result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
                return FormRestResponse.failure("Form Validation failed.", result);
            } else {
                status.setComplete();
                return RestResponse.success("A new static manual finding has been added to application");
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

		StringBuilder buffer = new StringBuilder();
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

        StringBuilder buffer = new StringBuilder();
		for (String sourceFile : sourceFileList) {
			if (sourceFile == null || sourceFile.equals(""))
				continue;
			buffer.append(sourceFile).append('\n');
		}
		return buffer.toString();
	}


}
