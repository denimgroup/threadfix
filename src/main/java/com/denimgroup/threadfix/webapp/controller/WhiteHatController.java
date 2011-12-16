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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.channel.SentinelChannelImporter;

@Controller
@RequestMapping("/configuration/whitehat")
public class WhiteHatController {
	private final ChannelTypeService channelTypeService;

	@Autowired
	public WhiteHatController(ChannelTypeService channelTypeService) {
		this.channelTypeService = channelTypeService;
	}

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		ChannelType channelType = channelTypeService.loadChannel(ChannelType.SENTINEL);
		model.addAttribute(channelType);
		String key = channelType.getApiKey();
				
		if (key == null || key.trim().isEmpty()) {
			return "redirect:/configuration/whitehat/change";
		} else {
			return "config/whitehat/index";
		}
	}

	@RequestMapping(method = RequestMethod.POST)
	public String submitKey(@ModelAttribute ChannelType channelType, BindingResult result, Model model, 
			SessionStatus status) {		
		
		if (channelType == null) {
			return "redirect:/configuration/whitehat/change";
		} else if (channelType.getApiKey() == null || channelType.getApiKey().trim().isEmpty()) {
			result.rejectValue("apiKey", "errors.required", new String [] { "API Key" }, null);
		} else if (channelType.getApiKey().length() > 254) {
			result.rejectValue("apiKey", "Maximum allowed length for this field is 255.");
		}
		
		if (result.hasErrors()) {
			return "config/whitehat/form";
		} else {			
			String key = channelType.getApiKey();
			ChannelType ct = channelTypeService.loadChannel(ChannelType.SENTINEL);
			ct.setApiKey(key);
			channelTypeService.storeChannel(ct);
			status.setComplete();
			return "redirect:/configuration/whitehat";
		}
	}

	@RequestMapping(value = "/change", method = RequestMethod.GET)
	public String changeKey(Model model) {
		ChannelType channelType = channelTypeService.loadChannel(ChannelType.SENTINEL);
		model.addAttribute(channelType);
		if (channelType.getApiKey() == null || channelType.getApiKey().trim().isEmpty()) {
			model.addAttribute("cancelToConfigPage", true);
		}
		
		return "config/whitehat/form";
	}
	
	@RequestMapping(value = "/jsoncheck", method = RequestMethod.POST)
	public @ResponseBody String readJson(@RequestBody String key) {
		if (key == null || key.isEmpty())
			return "No key supplied.";
				
		List<String> results = SentinelChannelImporter.getSites(key);
		
		if (results == null) {
			return "No response from Sentinel servers.";
		} else if (results.size() == 0) {
			return "Valid API Key, but no linked Sentinel Applications.";
		} else {
			StringBuilder builder = new StringBuilder();
			builder.append("Result sites:");
			
			for (String s : results) 
				builder.append('\n').append(s);
			
			return builder.toString();
		}
	}
}
