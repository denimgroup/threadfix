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

import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/channels/new")
@SessionAttributes("applicationChannel")
public class AddChannelController {

	private ApplicationChannelService applicationChannelService;
	private ChannelTypeService channelTypeService;
	private ApplicationService applicationService;
	
	private final Log log = LogFactory.getLog(AddChannelController.class);

	@Autowired
	public AddChannelController(ApplicationChannelService applicationChannelService,
			ChannelTypeService channelTypeService, ApplicationService applicationService) {
		this.applicationChannelService = applicationChannelService;
		this.applicationService = applicationService;
		this.channelTypeService = channelTypeService;
	}

	@ModelAttribute
	public List<Application> populateApplications() {
		return applicationService.loadAllActive();
	}

	@ModelAttribute
	public List<ChannelType> getChannelTypes() {
		return channelTypeService.getChannelTypeOptions(null);
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields(new String[] { "channelType.id", "application.id" });
	}

	@RequestMapping(method = RequestMethod.GET)
	public String addForm(ModelMap model) {
		model.addAttribute(new ApplicationChannel());
		return "config/channels/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String addSubmit(@Valid @ModelAttribute ApplicationChannel applicationChannel,
			BindingResult result, SessionStatus status) {
		if (result.hasErrors()) {
			return "config/channels/form";
		} else {
			// TODO pass a message back if the appChannel already exists
			if (!applicationChannelService.isDuplicate(applicationChannel)) {
				applicationChannelService.storeApplicationChannel(applicationChannel);
			}
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(user + " has created an Application Channel (id=" + applicationChannel.getId() + 
					") for the Application " + applicationChannel.getApplication().getName() + 
					" and the Channel Type " + applicationChannel.getChannelType().getName());

			status.setComplete();
			return "redirect:/configuration/channels";
		}
	}
}
