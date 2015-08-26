////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//     All rights reserved worldwide.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;

import java.io.File;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/configuration/settings")
@SessionAttributes("defaultConfiguration")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_SYSTEM_SETTINGS')")
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
    @Autowired
    private ScanService scanService;
    @Autowired
    private RequestUrlService requestUrlService;
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {

		String[] reports = {
				"dashboardTopLeft.id",
				"dashboardTopRight.id", "dashboardBottomLeft.id", "dashboardBottomRight.id",
				"applicationTopLeft.id", "applicationTopRight.id", "teamTopLeft.id", "teamTopRight.id",
                "fileUploadLocation", "deleteUploadedFiles", "baseUrl", "closeVulnWhenNoScannersReport"
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
    public String setupForm(Model model) {
        model.addAttribute("defaultConfiguration", defaultConfigService.loadCurrentConfiguration());
        return "config/systemSettings";
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping("/objects")
    public @ResponseBody Object getBaseObjects() {
        return success(addMapAttributes());
    }

    @RequestMapping("/currentlyUsedBaseUrl")
    public @ResponseBody RestResponse<String> getCurrentlyUsedBaseUrl(HttpServletRequest request) {
        return success(requestUrlService.getBaseUrlFromRequest(request));
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
    public @ResponseBody Object processSubmit(@ModelAttribute DefaultConfiguration defaultConfiguration,
                                              BindingResult bindingResult) {

        if (defaultConfiguration.getDeleteUploadedFiles()) {
            try {
                scanService.deleteScanFileLocations();
                defaultConfiguration.setDeleteUploadedFiles(false);
            } catch (RestIOException e) {
                return RestResponse.failure("Unable to delete files in 'File Upload Location' directory." + e.getMessage());
            }
        }

        if (defaultConfiguration.getSessionTimeout() != null && defaultConfiguration.getSessionTimeout() > 30) {
            bindingResult.reject("sessionTimeout", null, "30 is the maximum.");
        }

        if(defaultConfiguration.fileUploadLocationExists()) {
            File directory = new File(defaultConfiguration.getFileUploadLocation());
            if (!directory.exists()){
                bindingResult.rejectValue("fileUploadLocation", null, null, "Directory does not exist.");
            }
        }

        Map<String,String> errors = addReportErrors(defaultConfiguration);

        if (bindingResult.hasErrors() || errors.size() > 0) {

            // TODO look into this
            if (bindingResult.hasFieldErrors("proxyPort")) {
                bindingResult.reject("proxyPort", new Object[]{}, "Please enter a valid port number.");
            }

            return FormRestResponse.failure("Unable save System Settings. Try again.", bindingResult, errors);
        } else {
            defaultConfigService.saveConfiguration(defaultConfiguration);
            return success(defaultConfiguration);
        }
    }

    private Map<String,String> addReportErrors(DefaultConfiguration config) {
        Map<String,String> errors = map();

        if(defaultConfigService.reportDuplicateExists(config.getDashboardReports())) {
            errors.put("dashboardReport", "Cannot set more than one Dashboard report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(config.getApplicationReports())) {
            errors.put("applicationReport", "Cannot set more than one Application report placement to the same report.");
        }

        if(defaultConfigService.reportDuplicateExists(config.getTeamReports())) {
            errors.put("teamReport", "Cannot set more than one Team report placement to the same report.");
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
