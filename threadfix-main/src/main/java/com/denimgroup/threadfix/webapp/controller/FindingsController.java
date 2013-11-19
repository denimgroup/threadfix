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

import java.util.Calendar;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.VulnerabilityService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}")
public class FindingsController {
	
	public FindingsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(FindingsController.class);

	private FindingService findingService;
	private PermissionService permissionService;
	private VulnerabilityService vulnerabilityService;

	@Autowired
	public FindingsController(FindingService findingService,
			PermissionService PermissionService,
			VulnerabilityService vulnerabilityService) {
		this.findingService = findingService;
		this.permissionService = PermissionService;
		this.vulnerabilityService = vulnerabilityService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView finding(@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, 
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
		
		if (!permissionService.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return new ModelAndView("403");
		}
		
		Finding finding = findingService.loadFinding(findingId);
		if (finding == null){
			log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("scans/findingDetail");
		mav.addObject(finding);
		permissionService.addPermissions(mav, orgId, appId, Permission.CAN_MODIFY_VULNERABILITIES);
		return mav;
	}

	@RequestMapping(value = "merge", method = RequestMethod.GET)
	public String merge(@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, Model model,
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		Finding finding = findingService.loadFinding(findingId);

		if (finding != null && finding.getVulnerability() != null) {
			Vulnerability vuln = vulnerabilityService.loadVulnerability(finding.getVulnerability()
					.getId());
			List<Vulnerability> similarVulns = vulnerabilityService
					.loadSimilarVulnerabilities(vuln);
			similarVulns.remove(vuln);
			List<Vulnerability> sameGenericVulns = vulnerabilityService
					.loadAllByGenericVulnerabilityAndApp(vuln);
			sameGenericVulns.remove(vuln);

			model.addAttribute("finding", finding);
			model.addAttribute("similarVulns", similarVulns);
			model.addAttribute("sameGenericVulns", sameGenericVulns);
			return "scans/findingMerge";
		} else{
			log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
			throw new ResourceNotFoundException();
		}
	}
	
	@RequestMapping(value = "setVulnerability", method = RequestMethod.POST)
	public String setVulnerability(@RequestParam(required = false) String vulnerabilityId,
			@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, 
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, 
			Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		if (vulnerabilityId == null) {
			model.addAttribute("errorMessage", "No Vulnerability was selected. Please select one and try again.");
			return merge(findingId, scanId, model, orgId, appId);
		}
		
		Finding finding = findingService.loadFinding(findingId);
		Integer id = null;
		
		try {
			id = Integer.parseInt(vulnerabilityId);
		} catch (NumberFormatException e) {
			log.info("Bad vulnerabilityId provided '" + vulnerabilityId + "'. Should have been an integer");
			return merge(findingId, scanId, model, orgId, appId);
		}
		
		Vulnerability vulnerability = vulnerabilityService.loadVulnerability(id);
		
		if (finding != null && vulnerability != null) {
			
			if (finding.getVulnerability() != null && 
					finding.getVulnerability().getFindings().size() == 1) {
				finding.getVulnerability().closeVulnerability(null, Calendar.getInstance());
				vulnerabilityService.storeVulnerability(finding.getVulnerability());
			}
			
			finding.setVulnerability(vulnerability);
			findingService.storeFinding(finding);
		}
			
		return "redirect:/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId;
	}

}
