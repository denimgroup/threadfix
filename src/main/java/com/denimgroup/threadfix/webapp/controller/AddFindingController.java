////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
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
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelSeverityService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ScanMergeService;
import com.denimgroup.threadfix.service.UserService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/new")
@SessionAttributes("application")
public class AddFindingController {

	private ApplicationService applicationService;
	private ChannelTypeService channelTypeService;
	private ChannelSeverityService channelSeverityService;
	private ScanMergeService scanMergeService;
	private ChannelVulnerabilityService channelVulnerabilityService;
	private FindingService findingService;
	private UserService userService;

	private final Log log = LogFactory.getLog(AddChannelController.class);
	
	@Autowired
	public AddFindingController(ApplicationService applicationService,
			ScanMergeService scanMergeService, ChannelTypeService channelTypeService,
			ChannelSeverityService channelSeverityService,
			ChannelVulnerabilityService channelVulnerabilityService,
			FindingService findingService, UserService userService) {
		this.applicationService = applicationService;
		this.scanMergeService = scanMergeService;
		this.channelTypeService = channelTypeService;
		this.channelSeverityService = channelSeverityService;
		this.channelVulnerabilityService = channelVulnerabilityService;
		this.findingService = findingService;
		this.userService = userService;
	}

	@ModelAttribute
	public List<ChannelSeverity> populateChannelSeverity() {
		ChannelType channelType = channelTypeService
				.loadChannel(ChannelType.MANUAL);
		return channelSeverityService.loadByChannel(channelType);
	}
	
	@ModelAttribute("staticChannelVulnerablilityList")
	public List<String> populateStaticChannelVulnerablility(@PathVariable("appId") int appId){
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userService.loadUser(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = findingService.loadLatestStaticByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> cvList = new ArrayList<String>();
		for(Finding finding : findings) {
			if (finding == null || finding.getChannelVulnerability() == null || 
					finding.getChannelVulnerability().getCode() == null)
				continue;
			cvList.add(finding.getChannelVulnerability().getCode());
		}
		return removeDuplicates(cvList);
	}
	
	@ModelAttribute("dynamicChannelVulnerablilityList")
	public List<String> populateDynamicChannelVulnerablility(@PathVariable("appId") int appId){
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userService.loadUser(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = findingService.loadLatestDynamicByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> cvList = new ArrayList<String>();
		for(Finding finding : findings) {
			if (finding == null || finding.getChannelVulnerability() == null || 
					finding.getChannelVulnerability().getCode() == null)
				continue;
			cvList.add(finding.getChannelVulnerability().getCode());
		}
		return removeDuplicates(cvList);
	}
	
	@ModelAttribute("staticPathList")
	public List<String> populateStaticPath(@PathVariable("appId") int appId) {
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userService.loadUser(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = findingService.loadLatestStaticByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = new ArrayList<String>();
		for(Finding finding : findings) {
			if (finding == null || finding.getSurfaceLocation() == null || 
					finding.getSurfaceLocation().getPath() == null)
				continue;
			pathList.add(finding.getSurfaceLocation().getPath());
		}
		return removeDuplicates(pathList);
	}
	
	@ModelAttribute("dynamicPathList")
	public List<String> populateDynamicPath(@PathVariable("appId") int appId) {
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userService.loadUser(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = findingService.loadLatestDynamicByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = new ArrayList<String>();
		for(Finding finding : findings) {
			if (finding == null || finding.getSurfaceLocation() == null || 
					finding.getSurfaceLocation().getPath() == null)
				continue;
			pathList.add(finding.getSurfaceLocation().getPath());
		}
		return removeDuplicates(pathList);
	}
	
	private List<String> removeDuplicates(List<String> stringList) {
		if (stringList == null)
			return new ArrayList<String>();
		List<String> distinctStringList = new ArrayList<String>();
		for (int i = 0; i < stringList.size(); i++) {
			int j = 0;
			for (; j < i; j++) {
				if (stringList.get(i).equals(stringList.get(j))) {
					break;
				}
			}
			if (j == i)
				distinctStringList.add(stringList.get(i));
		}
		return distinctStringList;
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView addNewFinding(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId) {
		Application application = applicationService.loadApplication(appId);
		if (application == null)
			return new ModelAndView("redirect:/organizations/" + orgId);
			
		ModelAndView mav = new ModelAndView("scans/form");
		mav.addObject(new Finding());
		mav.addObject(application);
		return mav;
	}

	@RequestMapping(params = "staticSubmit", method = RequestMethod.POST)
	public String staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, ModelMap model) {
		if (result.hasErrors()) {
			model.addAttribute("static",true);
			FieldError originalError = result.getFieldError("dataFlowElements[0].lineNumber");
			if (originalError != null && originalError.getDefaultMessage()
					.startsWith("Failed to convert property value of type " +
							"'java.lang.String' to required type 'int'")) {
				result.rejectValue("dataFlowElements[0]", "errors.invalid", new String [] { "Line number" }, null);
			}
			return "scans/form";
		} else {
			if (finding != null && ((finding.getChannelVulnerability() == null) || 
									(finding.getChannelVulnerability().getCode() == null) ||
									(finding.getChannelVulnerability().getCode().isEmpty()))) {
				result.rejectValue("channelVulnerability.code", "errors.required", new String[]{ "Vulnerability" }, null);
			} else if (!channelVulnerabilityService.isValidManualName(finding.getChannelVulnerability().getCode())) {
				result.rejectValue("channelVulnerability.code", "errors.invalid", new String[]{ "Vulnerability" }, null);
			}
			
			if (finding != null && (finding.getLongDescription() == null || finding.getLongDescription().isEmpty())) {
				result.rejectValue("longDescription", "errors.required", new String [] { "Description" }, null);
			}
			
			if (result.hasErrors()) {
				model.addAttribute("static",true);
				return "scans/form";
			}
			
			String userName = SecurityContextHolder.getContext()
					.getAuthentication().getName();
			finding.setIsStatic(true);
			scanMergeService.processManualFinding(finding, appId, userName);

			log.debug(userName + " has added a new static finding to the Application " + 
					finding.getScan().getApplication().getName());
			status.setComplete();

			return "redirect:/organizations/" + orgId + "/applications/"
					+ appId;
		}
	}
	
	@RequestMapping(params = "dynamicSubmit", method = RequestMethod.POST)
	public String dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, ModelMap model) {
		if (result.hasErrors()) {
			model.addAttribute("static",false);
			return "scans/form";
		} else {
			if (finding == null || ((finding.getChannelVulnerability() == null) || 
									(finding.getChannelVulnerability().getCode() == null) ||
									(finding.getChannelVulnerability().getCode().isEmpty()))) {
				result.rejectValue("channelVulnerability.code", "errors.required", new String [] { "Vulnerability" }, null);
			} else if (!channelVulnerabilityService.isValidManualName(finding.getChannelVulnerability().getCode())) {
				result.rejectValue("channelVulnerability.code", "errors.invalid", new String [] { "Vulnerability" }, null);
			}
			
			if (finding != null && (finding.getLongDescription() == null || finding.getLongDescription().isEmpty())) {
				result.rejectValue("longDescription", "errors.required", new String [] { "Description" }, null);
			}
			
			if (result.hasErrors()) {
				model.addAttribute("static",false);
				return "scans/form";
			}
			
			String userName = SecurityContextHolder.getContext()
					.getAuthentication().getName();
			finding.setIsStatic(false);
			
			if (finding.getSurfaceLocation() != null && finding.getSurfaceLocation().getPath() != null) {
				try {
					URL resultURL = new URL(finding.getSurfaceLocation().getPath());
					finding.getSurfaceLocation().setUrl(resultURL);
				} catch (MalformedURLException e) {
					log.info("Path was not given in URL format, leaving it as it was.");
				}
			}
			
			scanMergeService.processManualFinding(finding, appId, userName);

			log.debug(userName + " has added a new dynamic finding to the Application " + 
					finding.getScan().getApplication().getName());
			status.setComplete();

			return "redirect:/organizations/" + orgId + "/applications/"
					+ appId;
		}
	}

	@RequestMapping(value = "/ajax_cwe", method = RequestMethod.POST)
	@ResponseBody
	public String readAjaxCWE(@RequestParam String prefix) {
		if (prefix == null || prefix.equals(""))
			return "";
		List<ChannelVulnerability> cVulnList = channelVulnerabilityService
				.loadSuggested(prefix);
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
