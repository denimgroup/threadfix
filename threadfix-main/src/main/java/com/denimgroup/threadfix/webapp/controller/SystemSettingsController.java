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
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
				"applicationTopLeft.id", "applicationTopRight.id", "teamTopLeft.id", "teamTopRight.id",
                "fileUploadLocation"
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

    @RequestMapping(method = RequestMethod.GET)
    public String setupForm() {
        return "config/systemSettings";
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping("/objects")
    public @ResponseBody Object getBaseObjects() {
        return success(addMapAttributes());
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping(value = "/checkLDAP", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> checkLDAP(@ModelAttribute DefaultConfiguration config) {
        long startTime = System.currentTimeMillis();
        if (ldapService.innerAuthenticate(config)) {
            long endTime = System.currentTimeMillis();
            return success("LDAP settings are valid. LDAP validation took: " + (endTime - startTime) + "ms.");
        } else {
            return failure("Unable to verify LDAP settings.");
        }
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping(method = RequestMethod.POST)
    public @ResponseBody Object processForm(@ModelAttribute DefaultConfiguration config, BindingResult bindingResult) {
        Map<String, Object> map = addMapAttributes();

        if (config.getSessionTimeout() != null && config.getSessionTimeout() > 30) {
            bindingResult.reject("sessionTimeout", null, "30 is the maximum.");
        }

        List<String> errors = addReportErrors(config);
        map.put("errors", errors);
        map.put("showErrors", errors.size() > 0);

        if (bindingResult.hasErrors() || errors.size() > 0) {

            // TODO look into this
            if (bindingResult.hasFieldErrors("proxyPort")) {
                bindingResult.reject("proxyPort", new Object[]{}, "Please enter a valid port number.");
            }

            return FormRestResponse.failure("Unable save System Settings. Try again.", bindingResult);
        } else {
            defaultConfigService.saveConfiguration(config);
            map.put("successMessage", "Configuration was saved successfully.");
            return success(map);
        }

    }

    private List<String> addReportErrors(DefaultConfiguration config) {
        List<String> errors = list();

        if(defaultConfigService.reportDuplicateExists(config.getDashboardReports())) {
            errors.add("Cannot set more than one Dashboard report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(config.getApplicationReports())) {
            errors.add("Cannot set more than one Application report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(config.getTeamReports())) {
            errors.add("Cannot set more than one Team report placement to the same report.");
        }

        return errors;
    }

    private Map<String, Object> addMapAttributes() {
        Map<String, Object> map = new HashMap<>();
        DefaultConfiguration configuration = defaultConfigurationWithMaskedPasswords();

        map.put("roleList", roleService.loadAll());
        map.put("applicationCount", applicationService.getApplicationCount());
        map.put("licenseCount", licenseService == null ? 0 : licenseService.getAppLimit());
        map.put("licenseExpirationDate", licenseService == null ? new Date() : licenseService.getExpirationDate().getTime());
        map.put("defaultConfiguration", configuration);
        map.put("dashboardReports", reportService.loadByLocationType(ReportLocation.DASHBOARD));
        map.put("applicationReports", reportService.loadByLocationType(ReportLocation.APPLICATION));
        map.put("teamReports", reportService.loadByLocationType(ReportLocation.TEAM));

        return map;
    }

    private DefaultConfiguration defaultConfigurationWithMaskedPasswords() {
        DefaultConfiguration configuration = defaultConfigService.loadCurrentConfiguration();

        if (configuration.getProxyPassword() != null && !configuration.getProxyPassword().isEmpty()) {
            configuration.setProxyPassword(DefaultConfiguration.MASKED_PASSWORD);
        }
        if (configuration.getActiveDirectoryCredentials() != null && !configuration.getActiveDirectoryCredentials().isEmpty()) {
            configuration.setActiveDirectoryCredentials(DefaultConfiguration.MASKED_PASSWORD);
        }

        return configuration;
    }
}
