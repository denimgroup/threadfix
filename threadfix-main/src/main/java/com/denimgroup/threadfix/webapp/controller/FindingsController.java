////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.VulnerabilityStatusService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Controller
public class FindingsController {
	
	private final SanitizedLogger log = new SanitizedLogger(FindingsController.class);

    @Autowired
	private FindingService findingService;
	@Autowired
    private VulnerabilityService vulnerabilityService;
	@Autowired
	private VulnerabilityStatusService vulnerabilityStatusService;

	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}", method = RequestMethod.GET)
	public  String finding(@PathVariable("findingId") int findingId,
						   @PathVariable("orgId") int orgId,
						   @PathVariable("appId") int appId,
						   Model model) {
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}

		Finding finding = findingService.loadFinding(findingId);
		if (finding == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
			throw new ResourceNotFoundException();
		}

		PermissionUtils.addPermissions(model, orgId, appId, Permission.CAN_MODIFY_VULNERABILITIES);

		return (EnterpriseTest.isEnterprise() &&
                findingService.hasSourceCode(finding) &&
                finding.getDataFlowElements().size() > 0) ? "scans/finding/index" : "scans/findingDetail";
	}

    @JsonView(AllViews.VulnerabilityDetail.class)
    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}/objects",
            method = RequestMethod.GET)
    public @ResponseBody Object getObjects(@PathVariable("findingId") int findingId) {

        Finding finding = findingService.loadFinding(findingId);
        if (finding == null) {
            log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
            throw new ResourceNotFoundException();
        }

        Map<String, Map<String, ?>> sourceCodeData = map(
                "files", findingService.getFilesWithVulnerabilities(finding),
                "lineNumbers", findingService.getFilesWithLineNumbers(finding)
        );

        return RestResponse.success(map(
                "finding", finding,
                "sourceCodeData", sourceCodeData,
                "isEnterprise", EnterpriseTest.isEnterprise()
        ));
    }

    @RequestMapping(value = "/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}/merge", method = RequestMethod.GET)
    public String merge(@PathVariable("findingId") int findingId,
                        Model model,
                        @PathVariable("orgId") int orgId,
                        @PathVariable("appId") int appId) {

        if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
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

	@JsonView(AllViews.VulnerabilityDetail.class)
	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnId}/findings/{findingId}/editDescription", method = RequestMethod.POST)
	@ResponseBody
	public Object editDescription(@PathVariable("orgId") int orgId,
								  @PathVariable("appId") int appId,
								  @PathVariable("vulnId") int vulnId,
								  @PathVariable("findingId") int findingId,
								  @RequestParam String longDescription,
								  Model model) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			RestResponse.failure("You do not have permission to modify vulnerabilities.");
		}

		log.info("Editing description for finding with Id " + findingId);

		Finding dbfinding = findingService.loadFinding(findingId);
		if (dbfinding != null && dbfinding.getVulnerability() != null) {
			dbfinding.setLongDescription(longDescription);
			findingService.storeFinding(dbfinding);
			return RestResponse.success(dbfinding);
		} else{
			return RestResponse.failure("Invalid finding Id.");
		}
	}
	
	@RequestMapping(value = "/organizations/{orgId}/applications/{appId}/scans/{scanId}/findings/{findingId}/setVulnerability", method = RequestMethod.POST)
	public String setVulnerability(@RequestParam(required = false) String vulnerabilityId,
			@PathVariable("findingId") int findingId,
			@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId, 
			Model model) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		if (vulnerabilityId == null) {
			model.addAttribute("errorMessage", "No Vulnerability was selected. Please select one and try again.");
			return merge(findingId, model, orgId, appId);
		}
		
		Finding finding = findingService.loadFinding(findingId);
		Integer id = null;
		
		try {
			id = Integer.parseInt(vulnerabilityId);
		} catch (NumberFormatException e) {
			log.info("Bad vulnerabilityId provided '" + vulnerabilityId + "'. Should have been an integer");
			return merge(findingId, model, orgId, appId);
		}
		
		Vulnerability vulnerability = vulnerabilityService.loadVulnerability(id);
		
		if (finding != null && vulnerability != null) {
			
			if (finding.getVulnerability() != null && 
					finding.getVulnerability().getFindings().size() == 1) {
				vulnerabilityStatusService.closeVulnerability(finding.getVulnerability(),  null, Calendar.getInstance(), false, true);
				vulnerabilityService.storeVulnerability(finding.getVulnerability());
			}
			
			finding.setVulnerability(vulnerability);
			findingService.storeFinding(finding);
		}
			
		return "redirect:/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId;
	}

	@RequestMapping(value = "/findings/{findingId}", method = RequestMethod.GET)
	public String viewFindingFromMapping(@PathVariable("findingId") int findingId) {

		Finding finding = findingService.loadFinding(findingId);
		if (finding == null ||
				finding.getScan() == null ||
				finding.getScan().getApplication() == null ||
				finding.getScan().getApplication().getOrganization() == null){
			log.warn(ResourceNotFoundException.getLogMessage("Finding", findingId));
			throw new ResourceNotFoundException();
		}

		int orgId = finding.getScan().getApplication().getOrganization().getId();
		int appId = finding.getScan().getApplication().getId();

		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return "403";
		}

		return "redirect:/organizations/" + orgId + "/applications/" + appId + "/scans/" + finding.getScan().getId() + "/findings/" + findingId;
	}
}
