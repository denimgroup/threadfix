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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/channels")
public class ChannelsController {

	private ApplicationChannelService applicationChannelService;

	@Autowired
	public ChannelsController(ApplicationChannelService applicationChannelService) {
		this.applicationChannelService = applicationChannelService;
	}

	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
		List<ApplicationChannel> appChannelList = applicationChannelService.loadAll();
		boolean hasActiveApps = false;
		
		if (appChannelList != null && appChannelList.size() >= 0) {
			for (ApplicationChannel appChannel : appChannelList) {
				if (appChannel != null && appChannel.getApplication() != null && 
						appChannel.getApplication().isActive()) {
					hasActiveApps = true;
					break;
				}
			}
		}
		
		model.addAttribute("hasActiveApps", hasActiveApps);
		model.addAttribute(applicationChannelService.loadAll());
		return "config/channels/index";
	}
}
