package com.denimgroup.threadfix.webapp.controller;


import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ManualFindingService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
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
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/vulnerabilities/{vulnerabilityId}/manual/{findingId}/edit")
@SessionAttributes("vulnerability")
public class EditManualFindingController {
	
	private final SanitizedLogger log = new SanitizedLogger(EditManualFindingController.class);

    @Autowired
	private FindingService findingService = null;
    @Autowired
    private ChannelVulnerabilityService channelVulnerabilityService;
    @Autowired
    private VulnerabilityService vulnerabilityService;
	@Autowired
    private ManualFindingService manualFindingService = null;

	public boolean isManual(Finding finding) {
		return !(finding == null || finding.getScan() == null || 
				finding.getScan().getApplicationChannel() == null ||
				finding.getScan().getApplicationChannel().getChannelType() == null ||
				finding.getScan().getApplicationChannel().getChannelType().getName() == null ||
				finding.getScan().getApplicationChannel().getChannelType().getName().equals(ScannerType.MANUAL.getFullName()));
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
	public String staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
            @PathVariable("findingId") int findingId,
            @PathVariable("vulnerabilityId") int vulnerabilityId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model,
            HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}

        Finding dbFinding = findingService.loadFinding(findingId);

        if (finding == null || dbFinding == null) {
            ControllerUtils.addErrorMessage(request, "Finding submitted is invalid");
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return "ajaxRedirectHarness";
        }
		if (isManual(dbFinding)) {
            ControllerUtils.addErrorMessage(request, "Finding submitted is not manual");
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return "ajaxRedirectHarness";
		} else if (!isAuthorizedForFinding(dbFinding)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
        finding.setId(findingId);
		if (result.hasErrors()) {
            finding.setIsStatic(true);
			return returnForm(model,appId, vulnerabilityId, finding);
		} else {
			finding.setIsStatic(true);
			boolean mergeResult = manualFindingService.processManualFindingEdit(finding, appId);
			
			if (!mergeResult) {
				log.warn("Merging failed for the dynamic manual finding submission.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("isStatic",true);
				return returnForm(model,appId, vulnerabilityId, finding);
			} else {
				status.setComplete();
                int newVulnId = finding.getVulnerability().getId();
//                String msg = "Static finding has been modified" +
//                        ((vulnerabilityId==newVulnId) ? "" :
//                                " and moved from Vulnerability " + vulnerabilityId + " to Vulnerability " + newVulnId);
                ControllerUtils.addSuccessMessage(request, "Static finding has been modified");
                model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + newVulnId);
                return "ajaxRedirectHarness";
			}
		}
	}
	
    @RequestMapping(params = "group=dynamic", method = RequestMethod.POST)
	public String dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
            @PathVariable("findingId") int findingId,
            @PathVariable("vulnerabilityId") int vulnerabilityId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model,
            HttpServletRequest request) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
        Finding dbFinding = findingService.loadFinding(findingId);

        if (finding == null || dbFinding == null) {
            ControllerUtils.addErrorMessage(request, "Finding submitted is invalid");
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return "ajaxRedirectHarness";
        }
		if (isManual(dbFinding)) {
            ControllerUtils.addErrorMessage(request, "Finding submitted is not manual");
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + vulnerabilityId);
            return "ajaxRedirectHarness";
		} else if (!isAuthorizedForFinding(dbFinding)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
        finding.setId(findingId);
		if (result.hasErrors()) {
            finding.setIsStatic(false);
			return returnForm(model, appId, vulnerabilityId, finding);
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
			
			boolean mergeResult = manualFindingService.processManualFindingEdit(finding, appId);
			if (!mergeResult) {
				log.warn("Merging failed for the dynamic manual finding submission.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("isStatic",false);
				return returnForm(model,appId, vulnerabilityId, finding);
			} else {
				status.setComplete();
                int newVulnId = finding.getVulnerability().getId();
//                String msg = "Dynamic finding has been modified" +
//                        ((vulnerabilityId==newVulnId) ? "" :
//                                " and moved from Vulnerability " + vulnerabilityId + " to Vulnerability " + newVulnId);
                ControllerUtils.addSuccessMessage(request, "Dynamic finding has been modified");
                model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId + "/vulnerabilities/" + newVulnId);
                return "ajaxRedirectHarness";
			}
		}
	}

    public String returnForm(Model model, int appId, int vulnId, Finding finding) {
        model.addAttribute("contentPage", "scans/finding/editManualFindingForm.jsp");
        model.addAttribute("vulnerability", vulnerabilityService.loadVulnerability(vulnId));
        model.addAttribute("manualSeverities", findingService.getManualSeverities());
        model.addAttribute("urlManualList", findingService.getAllManualUrls(appId));
        model.addAttribute("finding", finding);
        model.addAttribute("manualChannelVulnerabilities", channelVulnerabilityService.loadAllManual());
        return "ajaxFailureHarness";
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
