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

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ThreadFixUserDetails;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationCriticalityService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.webapp.viewmodels.QuickStartModel;

/**
 * @author bbeverly
 * @author mcollins
 * 
 */
@Controller
@RequestMapping("/organizations")
@SessionAttributes("quickStartModel")
public class OrganizationsController {
	
	public OrganizationsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(OrganizationsController.class);

	private OrganizationService organizationService = null;
	private ApplicationService applicationService = null;
	private ApplicationCriticalityService applicationCriticalityService = null;
	private ApplicationChannelService applicationChannelService = null;
	private PermissionService permissionService = null;
	private ChannelTypeService channelTypeService = null;
	private UploadScanController uploadScanController = null;
	private ScanService scanService = null;
	
	@Autowired
	public OrganizationsController(OrganizationService organizationService,
			ScanService scanService, ApplicationChannelService applicationChannelService,
			ChannelTypeService channelTypeService, PermissionService permissionService, 
			ApplicationService applicationService, UploadScanController uploadScanController,
			ApplicationCriticalityService applicationCriticalityService) {
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.applicationCriticalityService = applicationCriticalityService;
		this.applicationChannelService = applicationChannelService;
		this.permissionService = permissionService;
		this.channelTypeService = channelTypeService;
		this.scanService = scanService;
		this.uploadScanController = uploadScanController;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		addModelObjects(model);
		model.addAttribute("quickStartModel", new QuickStartModel());
		return "organizations/index";
	}
	
	private void addModelObjects(Model model) {
		List<Organization> organizations = organizationService.loadAllActiveFilter();

		// for quick start
		model.addAttribute("channels", channelTypeService.getChannelTypeOptions(null));
		
		applicationService.generateVulnerabilityReports(organizations);
		model.addAttribute(organizations);
		
		Object test = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		
		if (test instanceof ThreadFixUserDetails) {
			model.addAttribute("shouldChangePassword",
					!((ThreadFixUserDetails) test).hasChangedInitialPassword());
		}
	}

	@RequestMapping("/{orgId}")
	public ModelAndView detail(@PathVariable("orgId") int orgId) {
		Organization organization = organizationService.loadOrganization(orgId);
		List<Application> apps = permissionService.filterApps(organization);
		if (organization == null || !organization.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,null) && 
				(apps == null || apps.size() == 0)) {
			
			return new ModelAndView("403");
			
		} else {
			ModelAndView mav = new ModelAndView("organizations/detail");
			permissionService.addPermissions(mav, orgId, null, 
					Permission.CAN_MANAGE_APPLICATIONS, Permission.CAN_MANAGE_TEAMS);
			applicationService.generateVulnerabilityReports(organization);
			mav.addObject("apps", apps);
			mav.addObject(organization);
			return mav;
		}
	}

	@RequestMapping("/{orgId}/delete")
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TEAMS')")
	public String deleteOrg(@PathVariable("orgId") int orgId, SessionStatus status) {
		Organization org = organizationService.loadOrganization(orgId);
		if (org == null || !org.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Organization", orgId));
			throw new ResourceNotFoundException();
			
		} else if (!permissionService.isAuthorized(Permission.READ_ACCESS,orgId,null)){
			return "403";
			
		} else {
			organizationService.deactivateOrganization(org);
			status.setComplete();
			log.info("Organization soft deletion was successful on Organization " + org.getName() + ".");
			return "redirect:/organizations";
		}
	}
	
	@RequestMapping(method = RequestMethod.POST)
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TEAMS') " +
			"and hasRole('ROLE_CAN_MANAGE_APPLICATIONS') " +
			"and hasRole('ROLE_CAN_UPLOAD_SCANS')")
	public String quickStart(@Valid @ModelAttribute QuickStartModel quickStartModel, BindingResult result,
			SessionStatus status, Model model, HttpServletRequest request) {
		addModelObjects(model);
		if (result.hasErrors()) {
			return "organizations/index";
		} else {
			
			if (quickStartModel.getMultipartFile() == null ||
					quickStartModel.getMultipartFile().isEmpty()) {
				result.rejectValue("multipartFile", null, null, "You must submit a file.");
				return "organizations/index";
			}
			
			ChannelType type = null;
	
			if (quickStartModel.getChannelType().getId() == null || quickStartModel.getChannelType().getId() == -1) {
				String typeString = scanService.getScannerType(quickStartModel.getMultipartFile());
				if (typeString != null && !typeString.trim().isEmpty()) {
					type = channelTypeService.loadChannel(typeString);
				} else {
					result.rejectValue("multipartFile", null, null, 
							"ThreadFix was unable to find a suitable scanner type for the file. " +
							"Please choose one from the above list.");
				}
			} else {
				type = channelTypeService.loadChannel(quickStartModel.getChannelType().getId());
				if (type == null) {
					result.rejectValue("channelType", null, null, 
							"ThreadFix was unable to find the requested scanner type.");
				}
			}
			
			if (result.hasErrors()) {
				return "organizations/index";
			}
			
			Organization org = null;
			if (quickStartModel.getOrganization().getId() == null || quickStartModel.getOrganization().getId() == -1) {
				String teamName = quickStartModel.getOrganization().getName();
				if (teamName == null || teamName.trim().isEmpty() || 
						teamName.length() > Organization.NAME_LENGTH) {
					result.rejectValue("organization.name", null, null, 
							"This field cannot be empty.");
				}
				
				Organization dbOrg = organizationService.loadOrganization(teamName);
				if (dbOrg != null && dbOrg.isActive()) {
					result.rejectValue("organization.name", null, null, 
							"A team with this name already exists.");
				}
				
				org = new Organization();
				org.setName(teamName);
			} else {
				org = organizationService.loadOrganization(quickStartModel.getOrganization().getId());
				if (org == null) {
					result.rejectValue("organization.id", null, null, 
							"Invalid team selection.");
				}
			}
			
			if (result.hasErrors()) {
				return "organizations/index";
			}
			
			Application app = null;
			if (quickStartModel.getApplication().getId() == null || quickStartModel.getApplication().getId() == -1) {
				String appName = quickStartModel.getApplication().getName();
				if (appName == null || appName.trim().isEmpty() || 
						appName.length() > Application.NAME_LENGTH) {
					result.rejectValue("application.name", null, null, 
							"This field cannot be empty.");
				}
				
				if (applicationService.loadApplication(appName) != null) {
					result.rejectValue("application.name", null, null, 
							"An application with this name already exists.");
				}
				
				if (result.hasErrors()) {
					return "organizations/index";
				}
				
				app = new Application();
				app.setApplicationCriticality(applicationCriticalityService.
						loadApplicationCriticality(ApplicationCriticality.MEDIUM));
				app.setName(appName);
				app.setUrl("http://quick-started-app.com");
			} else {
				app = applicationService.loadApplication(quickStartModel.getApplication().getId());
				if (app == null) {
					result.rejectValue("application.id", null, null, 
							"Invalid application selection.");
					return "organizations/index";
				}
			}
			
			// we should be ok after here because we've checked the input to these items
			
			ApplicationChannel channel = null;
			
			if (app.getChannelList() == null || app.getChannelList().isEmpty()) {
				app.setChannelList(new ArrayList<ApplicationChannel>());
			} else {
				// it's ok to call app.getId() here because the app would have to come 
				// from the database in order for the channel list to be populated.
				channel = applicationChannelService.retrieveByAppIdAndChannelId(
						app.getId(), type.getId());
			}
			
			if (channel == null) {
				channel = new ApplicationChannel();
				channel.setChannelType(type);
				app.getChannelList().add(channel);
				channel.setApplication(app);
				channel.setScanList(new ArrayList<Scan>());
			}
			
			app.setOrganization(org);
			
			organizationService.storeOrganization(org);
			applicationService.storeApplication(app);
			
			uploadScanController.uploadSubmit(app.getId(), org.getId(), request, 
					channel.getId(), quickStartModel.getMultipartFile());
			
			return "redirect:/organizations/" + org.getId() + "/applications/" + app.getId();
		}
	}
}
