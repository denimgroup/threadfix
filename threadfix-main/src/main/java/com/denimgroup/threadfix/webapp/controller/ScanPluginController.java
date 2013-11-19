////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("/scanplugin")
public class ScanPluginController {

	private ChannelVulnerabilityService channelVulnerabilityService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(ScanPluginController.class);

	@Autowired
	public ScanPluginController(ChannelVulnerabilityService channelVulnerabilityService) {
		this.channelVulnerabilityService = channelVulnerabilityService;
	}
	
	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		
		model.addAttribute("pluginCheckBean", channelVulnerabilityService.checkPluginJar());
		
		return "scanplugin/channelVulnUpdate";
	}

	@RequestMapping(value = "/updateChannelVuln", method = RequestMethod.GET)
	public String doUpdate(Model model, HttpServletRequest request) {
		log.info("Start updating Channel Vulnerabilities");
		List<String[]> channelVulnUpdateResults = new ArrayList<>();
		
		try {
			channelVulnUpdateResults = channelVulnerabilityService.updateChannelVulnerabilities();
		} catch (URISyntaxException e) {
			model.addAttribute("errorMessage", "There was error when reading files.");
		}
		catch (IOException e) {
			model.addAttribute("errorMessage", "There was error when updating Channel Vulnerability.");
		}
		
		model.addAttribute("successMessage", "Vulnerability mappings were successfully updated.");
		
		model.addAttribute("pluginCheckBean", channelVulnerabilityService.checkPluginJar());
		
		model.addAttribute("resultList", channelVulnUpdateResults);
		log.info("Ended updating Channel Vulnerabilities");
		return "scanplugin/channelVulnUpdate";
	}
	
}

