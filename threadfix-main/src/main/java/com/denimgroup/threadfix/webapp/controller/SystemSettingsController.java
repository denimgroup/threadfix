////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

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
	@Autowired
	private ReportService reportService = null;
	@Autowired
	private ApplicationService applicationService;
	@Autowired(required = false)
	LicenseService licenseService;
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields("defaultRoleId", "globalGroupEnabled", "activeDirectoryBase",
                    "activeDirectoryURL", "activeDirectoryUsername", "activeDirectoryCredentials",
                    "proxyHost", "proxyPort", "proxyUsername", "proxyPassword", "shouldProxyVeracode",
                    "shouldProxyQualys", "shouldProxyTFS", "shouldProxyBugzilla", "shouldProxyJira",
                    "shouldProxyVersionOne", "shouldProxyHPQC", "shouldProxyWhiteHat", "shouldProxyTrustwaveHailstorm",
					"shouldProxyContrast", "shouldUseProxyCredentials", "sessionTimeout", "dashboardTopLeft.id",
                    "dashboardTopRight.id", "dashboardBottomLeft.id", "dashboardBottomRight.id",
                    "applicationTopLeft.id", "applicationTopRight.id", "teamTopLeft.id", "teamTopRight.id");
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

	@ModelAttribute("dashboardReports")
	public List<Report> populateDashboardReportTypes() {
		return reportService.loadByLocationType(ReportLocation.DASHBOARD);
	}

	@ModelAttribute("applicationReports")
	public List<Report> populateApplicationReportTypes() {
		return reportService.loadByLocationType(ReportLocation.APPLICATION);
	}

	@ModelAttribute("teamReports")
	public List<Report> populateTeamReportTypes() {
		return reportService.loadByLocationType(ReportLocation.TEAM);
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setupForm(Model model, HttpServletRequest request) {
		addModelAttributes(model, request);
		return "config/systemSettings";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String processForm(@ModelAttribute DefaultConfiguration configModel,
							  BindingResult bindingResult,
							  Model model,
							  HttpServletRequest request) {
		addModelAttributes(model, request);

        List<String> errors = list();

        if(defaultConfigService.reportDuplicateExists(configModel.getDashboardReports())) {
            errors.add("Cannot set more than one Dashboard report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(configModel.getApplicationReports())) {
            errors.add("Cannot set more than one Application report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(configModel.getTeamReports())) {
            errors.add("Cannot set more than one Team report placement to the same report.");
        }

        model.addAttribute("errors", errors);

        if (bindingResult.hasErrors() || errors.size() > 0) {

			// TODO look into this
			if (bindingResult.hasFieldErrors("proxyPort")) {
				bindingResult.reject("proxyPort", new Object[]{}, "Please enter a valid port number.");
			}

			return "config/systemSettings";
		} else {
			defaultConfigService.saveConfiguration(configModel);
			ControllerUtils.addSuccessMessage(request, "Configuration was saved successfully.");

			return "redirect:/configuration/settings";
		}

	}

	private void addModelAttributes(Model model, HttpServletRequest request) {
		model.addAttribute("isEnterprise", EnterpriseTest.isEnterprise());
		DefaultConfiguration configuration = defaultConfigService.loadCurrentConfiguration();

		if (configuration.getProxyPassword() != null && !configuration.getProxyPassword().isEmpty()) {
			configuration.setProxyPassword(DefaultConfiguration.MASKED_PASSWORD);
		}
		if (configuration.getActiveDirectoryCredentials() != null && !configuration.getActiveDirectoryCredentials().isEmpty()) {
			configuration.setActiveDirectoryCredentials(DefaultConfiguration.MASKED_PASSWORD);
		}

		model.addAttribute("applicationCount", applicationService.getApplicationCount());
		model.addAttribute("licenseCount", licenseService == null ? 0 : licenseService.getAppLimit());
		model.addAttribute("licenseExpirationDate", licenseService == null ? 0 : licenseService.getAppLimit());

		model.addAttribute("defaultConfiguration", configuration);
		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
	}

}
