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
import com.denimgroup.threadfix.service.RoleService;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
@RequestMapping("/configuration/settings")
@SessionAttributes("defaultConfiguration")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_SYSTEM_SETTINGS')")
public class SystemSettingsController {
	
	protected final SanitizedLogger log = new SanitizedLogger(SystemSettingsController.class);

    @Autowired
	private RoleService roleService = null;
	@Autowired
    private DefaultConfigService defaultConfigService = null;
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled", "activeDirectoryBase",
                    "activeDirectoryURL", "activeDirectoryUsername", "activeDirectoryCredentials",
                    "proxyHost", "proxyPort", "proxyUsername", "proxyPassword", "shouldProxyVeracode",
                    "shouldProxyQualys", "shouldProxyTFS", "shouldProxyBugzilla", "shouldProxyJira",
                    "shouldProxyVersionOne", "shouldProxyHPQC", "shouldProxyWhiteHat", "shouldProxyTrustwaveHailstorm",
                    "shouldUseProxyCredentials", "sessionTimeout");
		} else {
            // this should prevent any parameters from coming in.
            // We also need to check permissions on the server side though
			dataBinder.setAllowedFields();
		}
	}

	@ModelAttribute
	public List<Role> populateRoles() {
		return roleService.loadAll();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model, HttpServletRequest request) {
		model.addAttribute("isEnterprise", EnterpriseTest.isEnterprise());
		model.addAttribute("defaultConfiguration", defaultConfigService.loadCurrentConfiguration());
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		return "config/systemSettings";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processForm(@ModelAttribute DefaultConfiguration configModel,
			HttpServletRequest request) {
		
		defaultConfigService.saveConfiguration(configModel);
		ControllerUtils.addSuccessMessage(request, "Configuration was saved successfully.");
		
		return "redirect:/configuration/settings";
	}
	
}
