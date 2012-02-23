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

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;

@Controller
@RequestMapping("configuration/remoteproviders")
@SessionAttributes(value= {"remoteProviderType", "remoteProviderApplication"})
public class RemoteProvidersController {
	
	private final Log log = LogFactory.getLog(RemoteProvidersController.class);
	
	private RemoteProviderTypeService remoteProviderTypeService;
	private RemoteProviderApplicationService remoteProviderApplicationService;
	private OrganizationService organizationService;
	private ApplicationService applicationService;
	private ApplicationChannelService applicationChannelService;
	
	@Autowired
	public RemoteProvidersController(RemoteProviderTypeService remoteProviderTypeService,
			RemoteProviderApplicationService remoteProviderApplicationService,
			OrganizationService organizationService,
			ApplicationService applicationService,
			ApplicationChannelService applicationChannelService) {
		this.remoteProviderTypeService = remoteProviderTypeService;
		this.remoteProviderApplicationService = remoteProviderApplicationService;
		this.organizationService = organizationService;
		this.applicationService = applicationService;
		this.applicationChannelService = applicationChannelService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "apiKeyString", "username", "password", "application.id", "application.organization.id" });
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		log.info("Processing request for Remote Provider index.");
		List<RemoteProviderType> typeList = remoteProviderTypeService.loadAll();

		model.addAttribute("remoteProviders", typeList);
		return "config/remoteproviders/index";
	}
	
	@RequestMapping(value="/{typeId}/update", method = RequestMethod.GET)
	public String updateApps(@PathVariable("typeId") int typeId) {
		log.info("Processing request for RemoteProviderType update.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		remoteProviderApplicationService.updateApplications(remoteProviderType);
		remoteProviderTypeService.store(remoteProviderType);
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/import", method = RequestMethod.GET)
	public String importScan(@PathVariable("typeId") int typeId,
			@PathVariable("appId") int appId) {
		log.info("Processing request for scan import.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		if (remoteProviderApplication == null || remoteProviderApplication.getApplication() == null) {
			// TODO add an error to the session
			return "redirect:/configuration/remoteproviders/";
		}
		
		remoteProviderApplicationService.importScanForApplication(remoteProviderApplication);

		return "redirect:/organizations/" + 
				remoteProviderApplication.getApplication().getOrganization().getId() + 
				"/applications/" +
				remoteProviderApplication.getApplication().getId();
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.GET)
	public ModelAndView configureAppForm(@PathVariable("typeId") int typeId,
			@PathVariable("appId") int appId) {
		log.info("Processing request for Edit App page.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		
		ModelAndView modelAndView = new ModelAndView("config/remoteproviders/edit");
		modelAndView.addObject("remoteProviderApplication", remoteProviderApplication);
		modelAndView.addObject("organizationList", organizationService.loadAllActive());
		return modelAndView;
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.POST)
	public String configureAppSubmit(@PathVariable("typeId") int typeId,
			@Valid @ModelAttribute RemoteProviderApplication remoteProviderApplication, 
			BindingResult result, SessionStatus status) {
		if (result.hasErrors() || remoteProviderApplication.getApplication() == null) {
			return "config/remoteproviders/edit";
		} else {
			Application application = applicationService.loadApplication(
					remoteProviderApplication.getApplication().getId());
			
			if (application.getRemoteProviderApplications() == null) {
				application.setRemoteProviderApplications(new ArrayList<RemoteProviderApplication>());
			}
			if (!application.getRemoteProviderApplications().contains(remoteProviderApplication)) {
				application.getRemoteProviderApplications().add(remoteProviderApplication);
				remoteProviderApplication.setApplication(application);
			}
			
			ChannelType type = remoteProviderApplication.getRemoteProviderType().getChannelType();
			
			if (application.getChannelList() == null || application.getChannelList().size() == 0) {
				application.setChannelList(new ArrayList<ApplicationChannel>());
				ApplicationChannel channel = new ApplicationChannel();
				channel.setApplication(application);
				if (remoteProviderApplication.getRemoteProviderType() != null && 
						remoteProviderApplication.getRemoteProviderType().getChannelType() != null) {
					channel.setChannelType(remoteProviderApplication.getRemoteProviderType().getChannelType());
					applicationChannelService.storeApplicationChannel(channel);
				}
				remoteProviderApplication.setApplicationChannel(channel);
				application.getChannelList().add(channel);
				
			} else {
				
				for (ApplicationChannel applicationChannel : application.getChannelList()) {
					if (applicationChannel.getChannelType().getName().equals(type.getName())) {
						remoteProviderApplication.setApplicationChannel(applicationChannel);
						break;
					}
				}
			}
			
			remoteProviderApplicationService.store(remoteProviderApplication);
			applicationService.storeApplication(application);

			status.setComplete();
			return "redirect:/configuration/remoteproviders";
		}
	}
	
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.GET)
	public ModelAndView configureStart(@PathVariable("typeId") int typeId) {
		log.info("Processing request for Remote Provider config page.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		
		ModelAndView modelAndView = new ModelAndView("config/remoteproviders/configure");
		modelAndView.addObject(remoteProviderType);
		return modelAndView;
	}
	
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.POST)
	public String configureFinish(@PathVariable("typeId") int typeId,
			@Valid @ModelAttribute RemoteProviderType remoteProviderType, 
			BindingResult result, SessionStatus status) {
		if (result.hasErrors()) {
			return "config/remoteproviders/configure";
		} else {
			RemoteProviderType databaseRemoteProviderType = remoteProviderTypeService.load(typeId);
			
			// TODO move to service layer
			if (databaseRemoteProviderType == null || databaseRemoteProviderType.getUsername() == null ||
					(remoteProviderType != null && remoteProviderType.getUsername() != null &&
					!databaseRemoteProviderType.getUsername().equals(remoteProviderType.getUsername()))) {
			
				log.warn("Provider username has changed, deleting old apps.");
				
				remoteProviderApplicationService.deleteApps(databaseRemoteProviderType);

				remoteProviderType.setRemoteProviderApplications(
						remoteProviderApplicationService.getApplications(remoteProviderType));
				
				if (remoteProviderType.getRemoteProviderApplications() != null) {
					for (RemoteProviderApplication remoteProviderApplication : remoteProviderType.getRemoteProviderApplications()) {
						remoteProviderApplicationService.store(remoteProviderApplication);
					}
				}
			}
			
			remoteProviderTypeService.store(remoteProviderType);

			status.setComplete();
			return "redirect:/configuration/remoteproviders";
		}
	}
}
