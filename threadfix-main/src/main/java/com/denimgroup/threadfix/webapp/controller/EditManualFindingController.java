package com.denimgroup.threadfix.webapp.controller;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.ManualFindingService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/manual/{findingId}")
@SessionAttributes("finding")
public class EditManualFindingController {
	
	private final SanitizedLogger log = new SanitizedLogger(EditManualFindingController.class);
	
	private FindingService findingService = null;
	private PermissionService permissionService = null;
	private ManualFindingService manualFindingService = null;
	
	@Autowired
	public EditManualFindingController(PermissionService permissionService, 
			FindingService findingService,
			ManualFindingService manualFindingService) {
		this.findingService = findingService;
		this.permissionService = permissionService;
		this.manualFindingService = manualFindingService;
	}
	
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
			return permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, 
					finding.getScan().getApplication().getOrganization().getId(), 
					finding.getScan().getApplication().getId());
		}
		
		throw new ResourceNotFoundException();
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			@PathVariable("findingId") int findingId, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
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
	
	@RequestMapping(params = "staticSubmit", method = RequestMethod.POST)
	public String staticSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		if (isManual(finding)) {
			return "redirect:/organizations/" + orgId + "/applications/" + appId;
		} else if (!isAuthorizedForFinding(finding)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
			
		if (result.hasErrors()) {
			model.addAttribute("isStatic",true);
			return returnForm(model,finding);
		} else {

			finding.setIsStatic(true);
			boolean mergeResult = manualFindingService.processManualFindingEdit(finding, appId);
			
			if (!mergeResult) {
				log.warn("Merging failed for the dynamic manual finding submission.");
				result.rejectValue("channelVulnerability.code", null, null, "Merging failed.");
				model.addAttribute("isStatic",true);
				return returnForm(model,finding);
			} else {
				status.setComplete();
				return "redirect:/organizations/" + orgId + "/applications/" + appId;
			}
		}
	}
	
	@RequestMapping(params = "dynamicSubmit", method = RequestMethod.POST)
	public String dynamicSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute Finding finding, BindingResult result,
			SessionStatus status, Model model) {
		
		if (!permissionService.isAuthorized(Permission.CAN_MODIFY_VULNERABILITIES, orgId, appId)) {
			return "403";
		}
		
		if (isManual(finding)) {
			return "redirect:/organizations/" + orgId + "/applications/" + appId;
		} else if (!isAuthorizedForFinding(finding)) {
			return "403";
		}
		
		findingService.validateManualFinding(finding, result);
		
		if (result.hasErrors()) {
			model.addAttribute("isStatic",false);
			return returnForm(model, finding);
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
				return returnForm(model,finding);
			} else {
				status.setComplete();
				return "redirect:/organizations/" + orgId + "/applications/" + appId;
			}
		}
	}
	
	public String returnForm(Model model, Finding finding) {
		if (finding != null && finding.getScan() != null && 
				finding.getScan().getApplication() != null) {
			model.addAttribute("application", finding.getScan().getApplication());
		}
		return "scans/form";
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
