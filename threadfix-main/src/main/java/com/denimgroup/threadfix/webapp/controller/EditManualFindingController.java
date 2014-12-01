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
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnerabilityId}/manual/{findingId}/edit")
@SessionAttributes("vulnerability")
public class EditManualFindingController {
	
	private final SanitizedLogger log = new SanitizedLogger(EditManualFindingController.class);

    @Autowired
	private FindingService findingService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
	@Autowired
    private ManualFindingService manualFindingService;
    @Autowired
    private QueueSender queueSender;
    @Autowired
    private ScanService scanService;

	public boolean isManual(Finding finding) {
        return finding != null && ScannerType.MANUAL.getFullName().equals(finding.getChannelNameOrNull());
	}
	
	public boolean isAuthorizedForFinding(Finding finding) {
		if (finding != null && finding.getScan() != null &&
				finding.getScan().getApplication() != null && 
				finding.getScan().getApplication().getId() != null &&
				finding.getScan().getApplication().getOrganization() != null &&
				finding.getScan().getApplication().getOrganization().getId() != null) {
			return PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES,
                    finding.getScan().getApplication().getOrganization().getId(),
                    finding.getScan().getApplication().getId());
		}
		
		throw new ResourceNotFoundException();
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			@PathVariable("findingId") int findingId, Model model) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		Finding finding = findingService.loadFinding(findingId);
		
		if (isManual(finding)) {
			return "redirect:/organizations/" + orgId + "/applications/" + appId;
		} else if (!isAuthorizedForFinding(finding)) {
			return "403";
		}
		
		model.addAttribute("finding", finding);
		
		if (finding != null && finding.getScan() != null && 
				finding.getScan().getApplication() != null) {
			model.addAttribute("application", finding.getScan().getApplication());
			model.addAttribute("isStatic", finding.getIsStatic());
		}
		
		return "scans/form";
	}
	
    @RequestMapping(params = "group=static", method = RequestMethod.POST)
	public @ResponseBody RestResponse<Vulnerability> staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
            @PathVariable("findingId") int findingId,
            @PathVariable("vulnerabilityId") int vulnerabilityId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model,
            HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
            return RestResponse.failure("You don't have permission to modify vulnerabilities.");
		}

        Finding dbFinding = findingService.loadFinding(findingId);

        if (finding == null || dbFinding == null) {
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return RestResponse.failure("Finding submitted is invalid.");
        }
		if (!isManual(dbFinding)) {
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return RestResponse.failure("Finding submitted is not manual.");
		} else if (!isAuthorizedForFinding(dbFinding)) {
            return RestResponse.failure("You don't have permission to modify finding.");
		}

		findingService.validateManualFinding(finding, result, true);
//        finding.setId(findingId);
		if (result.hasErrors()) {
            finding.setIsStatic(true);
            return FormRestResponse.failure("Form Validation failed.", result);
		} else {
			finding.setIsStatic(true);

            copyFinding(finding, dbFinding);

			boolean mergeResult = manualFindingService.processManualFindingEdit(dbFinding, appId);
			
			if (!mergeResult) {
				log.warn("Merging failed for the dynamic manual finding submission.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("isStatic",true);
                return FormRestResponse.failure("Form Validation failed.", result);
			} else {
				status.setComplete();
                updateVulnAfterEdit(vulnerabilityId, dbFinding, appId);
                int newVulnId = dbFinding.getVulnerability().getId();
//                String msg = "Static finding has been modified" +
//                        ((vulnerabilityId==newVulnId) ? "" :
//                                " and moved from Vulnerability " + vulnerabilityId + " to Vulnerability " + newVulnId);
                return RestResponse.success(vulnerabilityService.loadVulnerability(newVulnId));
			}
		}
	}
	
    @RequestMapping(params = "group=dynamic", method = RequestMethod.POST)
	public @ResponseBody RestResponse<Vulnerability> dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
            @PathVariable("findingId") int findingId,
            @PathVariable("vulnerabilityId") int vulnerabilityId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model,
            HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
            return RestResponse.failure("You don't have permission to modify vulnerabilities.");
		}
        Finding dbFinding = findingService.loadFinding(findingId);

        if (finding == null || dbFinding == null) {
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return RestResponse.failure("Finding submitted is invalid.");
        }
		if (!isManual(dbFinding)) {
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return RestResponse.failure("Finding submitted is not manual.");
		} else if (!isAuthorizedForFinding(dbFinding)) {
            return RestResponse.failure("You don't have permission to modify finding.");
		}
		
		findingService.validateManualFinding(finding, result, false);
//        finding.setId(findingId);
		if (result.hasErrors()) {
            finding.setIsStatic(false);
            return FormRestResponse.failure("Form Validation failed.", result);
		} else {
			finding.setIsStatic(false);
			if (finding.getSurfaceLocation() != null && finding.getSurfaceLocation().getPath() != null) {
				try {
					URL resultURL = new URL(finding.getSurfaceLocation().getPath());
					finding.getSurfaceLocation().setUrl(resultURL);
				} catch (MalformedURLException e) {
					log.info("Path of '" + finding.getSurfaceLocation().getPath() + "' was not given in URL format, leaving it as it was.");
				}
			}
			copyFinding(finding, dbFinding);
			boolean mergeResult = manualFindingService.processManualFindingEdit(dbFinding, appId);
			if (!mergeResult) {
				log.warn("Merging failed for the dynamic manual finding submission.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("isStatic",false);
                return FormRestResponse.failure("Form Validation failed.", result);
			} else {
				status.setComplete();
                updateVulnAfterEdit(vulnerabilityId, dbFinding, appId);
                int newVulnId = dbFinding.getVulnerability().getId();
//                String msg = "Dynamic finding has been modified" +
//                        ((vulnerabilityId==newVulnId) ? "" :
//                                " and moved from Vulnerability " + vulnerabilityId + " to Vulnerability " + newVulnId);
                model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + newVulnId);
                return RestResponse.success(vulnerabilityService.loadVulnerability(newVulnId));
			}
		}
	}

    private void updateVulnAfterEdit(int vulnerabilityId, Finding dbFinding, int appId) {
        int newVulnId = dbFinding.getVulnerability().getId();

        if (newVulnId != vulnerabilityId) {
            Vulnerability oldVuln = vulnerabilityService.loadVulnerability(vulnerabilityId);
            if (oldVuln.getFindings() == null || oldVuln.getFindings().size() == 0 ||
                    (oldVuln.getFindings().size() == 1 && oldVuln.getFindings().get(0).getId() == dbFinding.getId() )) {
                oldVuln.getApplication().getVulnerabilities().remove(oldVuln);
                oldVuln.setApplication(null);
                vulnerabilityService.deleteVulnerability(oldVuln);
                Scan scan = manualFindingService.getManualScan(appId);
                scan.setNumberTotalVulnerabilities(scan.getNumberTotalVulnerabilities()-1);
                scanService.storeScan(scan);
            }

        }
        queueSender.updateCachedStatistics(appId);
    }

    private void copyFinding(Finding finding, Finding dbFinding) {
        dbFinding.setIsStatic(finding.getIsStatic());

        dbFinding.setChannelVulnerability(finding.getChannelVulnerability());

        SurfaceLocation surfaceLocation = dbFinding.getSurfaceLocation() == null ? new SurfaceLocation() : dbFinding.getSurfaceLocation();
        if (finding.getSurfaceLocation() != null) {
            surfaceLocation.setPath(finding.getSurfaceLocation().getPath());
            surfaceLocation.setParameter(finding.getSurfaceLocation().getParameter());
            dbFinding.setSurfaceLocation(surfaceLocation);
        } else
            dbFinding.setSurfaceLocation(null);


        List<DataFlowElement> dataFlowElements = dbFinding.getDataFlowElements() == null ? new ArrayList<DataFlowElement>() : dbFinding.getDataFlowElements();
        if (finding.getDataFlowElements() != null && finding.getDataFlowElements().size() > 0) {
            DataFlowElement element = dataFlowElements.size() == 0 ? new DataFlowElement() : dataFlowElements.get(0);
            element.setSourceFileName(finding.getDataFlowElements().get(0).getSourceFileName());
            element.setLineNumber(finding.getDataFlowElements().get(0).getLineNumber());
            if (dataFlowElements.size()==0)
                dataFlowElements.add(element);
            dbFinding.setDataFlowElements(dataFlowElements);
        } else
            dbFinding.setDataFlowElements(null);

        dbFinding.setChannelSeverity(finding.getChannelSeverity());
        dbFinding.setLongDescription(finding.getLongDescription());
    }


	@ModelAttribute("channelSeverityList")
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
}
