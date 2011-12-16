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

import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.VulnerabilityService;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}")
public class FindingsController {
	
	private final Log log = LogFactory.getLog(FindingsController.class);

	private FindingService findingService;
	private VulnerabilityService vulnerabilityService;

	@Autowired
	public FindingsController(FindingService findingService,
			VulnerabilityService vulnerabilityService) {
		this.findingService = findingService;
		this.vulnerabilityService = vulnerabilityService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView finding(@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, 
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
		
		Finding finding = findingService.loadFinding(findingId);
		if (finding == null){
			log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("scans/findingDetail");
		mav.addObject(finding);
		return mav;
	}

	@RequestMapping(value = "merge", method = RequestMethod.GET)
	public String merge(@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, Model model,
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
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
	public String setVulnerability(@RequestParam String vulnerabilityId,
			@PathVariable("findingId") int findingId,
			@PathVariable("scanId") int scanId, 
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, 
			Model model) {
		
		Finding finding = findingService.loadFinding(findingId);
		Integer id = null;
		
		try {
			id = Integer.parseInt(vulnerabilityId);
		} catch (NumberFormatException e) {
			return merge(findingId, scanId, model, orgId, appId);
		}
		
		Vulnerability vulnerability = null;
		if (id != null)
			vulnerability = vulnerabilityService.loadVulnerability(id);
		
		if (finding != null && vulnerability != null) {
			finding.setVulnerability(vulnerability);
			findingService.storeFinding(finding);
		}
			
		return merge(findingId, scanId, model, orgId, appId);
	}

}
