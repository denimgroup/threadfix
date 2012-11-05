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

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/addChannel")
@SessionAttributes("applicationChannel")
public class AddApplicationChannelController {

	private ApplicationChannelService applicationChannelService;
	private ChannelTypeService channelTypeService;
	private ApplicationService applicationService;
	private OrganizationService organizationService;
	
	private final SanitizedLogger log = new SanitizedLogger(AddApplicationChannelController.class);

	@Autowired
	public AddApplicationChannelController(ApplicationChannelService applicationChannelService,
			ChannelTypeService channelTypeService, ApplicationService applicationService,
			OrganizationService organizationService) {
		this.applicationChannelService = applicationChannelService;
		this.applicationService = applicationService;
		this.channelTypeService = channelTypeService;
		this.organizationService = organizationService;
	}
	
	public AddApplicationChannelController(){}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "channelType.id" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public String addForm(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId, ModelMap model) {

		if (!organizationService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return "403";
		}
		
		Application application = applicationService.loadApplication(appId);
		
		if (application == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		model.addAttribute(channelTypeService.getChannelTypeOptions(application));
		
		model.addAttribute(application);
		model.addAttribute(new ApplicationChannel());
		return "scans/addChannel";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String addChannelSubmit(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@Valid @ModelAttribute ApplicationChannel applicationChannel, BindingResult result,
			SessionStatus status) {
		
		if (!organizationService.isAuthorized(Permission.CAN_UPLOAD_SCANS, orgId, appId)) {
			return "403";
		}
		
		if (result.hasErrors()) {
			return "config/channels/form";
		} else {
			Application application = applicationService.loadApplication(appId);
			applicationChannel.setApplication(application);
			if (!applicationChannelService.isDuplicate(applicationChannel)) {
				applicationChannelService.storeApplicationChannel(applicationChannel);
				
				String user = SecurityContextHolder.getContext().getAuthentication().getName();

				log.debug("An Application Channel (id=" + applicationChannel.getId() + 
						") has successfully been created by " + user + 
						" for the Application " + application.getName() + 
						" and the Channel Type " + applicationChannel.getChannelType().getName());
			} else {
				log.info("That applicationChannel had already been created.");
			}
			
			status.setComplete();
			return "redirect:/organizations/" + orgId + "/applications/" + appId + "/scans/upload";
		}
	}
}
