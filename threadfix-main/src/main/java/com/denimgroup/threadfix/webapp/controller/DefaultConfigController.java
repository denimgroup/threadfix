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

import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/configuration/defaults")
@SessionAttributes("defaultConfiguration")
public class DefaultConfigController {
	
	protected final SanitizedLogger log = new SanitizedLogger(DefaultConfigController.class);

	private RoleService roleService = null;
	private DefaultConfigService defaultConfigService = null;
	
	@Autowired
	public DefaultConfigController(DefaultConfigService defaultConfigService,
			RoleService roleService) {
		this.roleService = roleService;
		this.defaultConfigService = defaultConfigService;
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled", "activeDirectoryBase",
                    "activeDirectoryURL", "activeDirectoryUsername", "activeDirectoryCredentials");
		} else {
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled");
		}
	}
	
	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model, HttpServletRequest request) {
		model.addAttribute("ldap_plugin", EnterpriseTest.isEnterprise());
		model.addAttribute("defaultConfiguration", defaultConfigService.loadCurrentConfiguration());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		return "config/defaults";
	}
	
	@RequestMapping(method = RequestMethod.POST)
	public String processForm(@ModelAttribute DefaultConfiguration configModel,
			HttpServletRequest request) {
		
		defaultConfigService.saveConfiguration(configModel);
		ControllerUtils.addSuccessMessage(request, "Configuration was saved successfully.");
		
		return "redirect:/configuration/defaults";
	}
	
}
