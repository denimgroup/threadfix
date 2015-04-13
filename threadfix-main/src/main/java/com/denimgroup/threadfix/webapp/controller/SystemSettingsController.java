////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//     All rights reserved worldwide.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/configuration/settings")
@SessionAttributes("defaultConfiguration")
public class SystemSettingsController {
	
	protected final SanitizedLogger log = new SanitizedLogger(SystemSettingsController.class);

	@Autowired(required = false)
	private LdapService ldapService;

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

		String[] reports = {
				"dashboardTopLeft.id",
				"dashboardTopRight.id", "dashboardBottomLeft.id", "dashboardBottomRight.id",
				"applicationTopLeft.id", "applicationTopRight.id", "teamTopLeft.id", "teamTopRight.id"
		};

		String[] otherSections = {
				"defaultRoleId", "globalGroupEnabled", "activeDirectoryBase",
				"activeDirectoryURL", "activeDirectoryUsername", "activeDirectoryCredentials",
				"proxyHost", "proxyPort", "proxyUsername", "proxyPassword", "shouldProxyVeracode",
				"shouldProxyQualys", "shouldProxyTFS", "shouldProxyBugzilla", "shouldProxyJira",
				"shouldProxyVersionOne", "shouldProxyHPQC", "shouldProxyWhiteHat", "shouldProxyTrustwaveHailstorm",
				"shouldProxyContrast", "shouldUseProxyCredentials", "sessionTimeout"
		};

		if (EnterpriseTest.isEnterprise()) {
			dataBinder.setAllowedFields(ArrayUtils.addAll(otherSections, reports));
		} else {
			dataBinder.setAllowedFields(reports);
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

	@ResponseBody
	@RequestMapping(value="getLDAPSettings", method = RequestMethod.GET)
	public RestResponse<DefaultConfiguration> getLDAPSettings(@ModelAttribute DefaultConfiguration configModel, HttpServletRequest request)
	{
		DefaultConfiguration configuration = defaultConfigService.loadCurrentConfiguration();

		if (configuration.getProxyPassword() != null && !configuration.getProxyPassword().isEmpty()) {
			configuration.setProxyPassword(DefaultConfiguration.MASKED_PASSWORD);
		}
		if (configuration.getActiveDirectoryCredentials() != null && !configuration.getActiveDirectoryCredentials().isEmpty()) {
			configuration.setActiveDirectoryCredentials(DefaultConfiguration.MASKED_PASSWORD);
		}

		return success(configModel);
	}

	@ResponseBody
    @RequestMapping(value = "/checkLDAP", method = RequestMethod.POST)
    public RestResponse<String> checkLDAP(@ModelAttribute DefaultConfiguration configModel,
                            Model model,
                            HttpServletRequest request) {
		addModelAttributes(model, request);

		long startTime = System.currentTimeMillis();
        if (ldapService.innerAuthenticate(configModel)) {
			long endTime = System.currentTimeMillis();
			return success("LDAP settings are valid. LDAP validation took: " + (endTime - startTime) + "ms.");
		} else {
			return failure("Unable to verify LDAP settings.");
		}
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

		if (configModel.getSessionTimeout() != null && configModel.getSessionTimeout() > 30) {
			bindingResult.reject("sessionTimeout", null, "30 is the maximum.");
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
