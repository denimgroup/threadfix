////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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
import com.denimgroup.threadfix.data.entities.CSVExportField;
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
import java.beans.PropertyEditorSupport;
import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
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
    @Autowired
    private UserService userService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
		String[] reports = {
				"dashboardTopLeft.id",
				"dashboardTopRight.id", "dashboardBottomLeft.id", "dashboardBottomRight.id",
				"applicationTopLeft.id", "applicationTopRight.id", "teamTopLeft.id", "teamTopRight.id",
                "fileUploadLocation", "deleteUploadedFiles", "csvExportFields[*]", "baseUrl", 
                "closeVulnWhenNoScannersReport"
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

        dataBinder.registerCustomEditor(CSVExportField.class, "csvExportFields[*]", new CSVExportFieldEnumConverter(CSVExportField.class));
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
            return failure("Unable to verify LDAP settings. They are invalid or not configured.");
        }
    }

    @JsonView(AllViews.FormInfo.class)
    @RequestMapping(method = RequestMethod.POST)
    public @ResponseBody Object processSubmit(@ModelAttribute DefaultConfiguration defaultConfiguration,
                                              HttpServletRequest request,
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

        if (defaultConfiguration.fileUploadLocationExists()) {
            checkingFolder(defaultConfiguration, bindingResult);
        }

        // This was added because Spring autobinding was not saving the export fields properly
        List<CSVExportField> exportFields = list();
        Map<String, String[]> params = request.getParameterMap();
        int index = 0;

        while (index != -1) {
            String key = "csvExportFields["+index+"]";
            String [] enumValue = params.get(key);

            if (enumValue != null) {
                exportFields.add(CSVExportField.valueOf(enumValue[0]));
                index++;
            } else {
                index = -1;
            }
        }

        defaultConfiguration.setCsvExportFields(exportFields);

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

        map.put("exportFields", defaultConfigService.getUnassignedExportFields(configuration.getCsvExportFields()));
        map.put("exportFieldDisplayNames", CSVExportField.getExportFields());
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

    private void checkingFolder(DefaultConfiguration defaultConfiguration,
                                BindingResult bindingResult){
        File directory = new File(defaultConfiguration.getFileUploadLocation());
        if (!directory.exists()){
            bindingResult.rejectValue("fileUploadLocation", null, null, "Directory does not exist.");
        } else if (!directory.isDirectory()){
            bindingResult.rejectValue("fileUploadLocation", null, null, "Is not a directory.");
        } else {
            try {
                // Check permission: try to create a temp file. In Windows, file.canWrite() doesn't work for example c:\ folder
                File tempFile = new File(defaultConfiguration.getFileUploadLocation() + File.separator + "temp");
                if (!(tempFile.createNewFile())) {
                    bindingResult.rejectValue("fileUploadLocation", null, null, "Unable to create files in this directory.");
                } else {
                    // Delete temp file
                    tempFile.delete();
                }
            } catch (IOException e) {
                bindingResult.rejectValue("fileUploadLocation", null, null, "Unable to create files in this directory. Message was: " + e.getMessage());
            }

        }
    }

    class CSVExportFieldEnumConverter<T extends Enum<T>> extends PropertyEditorSupport {

        private final Class<T> typeParameterClass;

        public CSVExportFieldEnumConverter(Class<T> typeParameterClass) {
            super();
            this.typeParameterClass = typeParameterClass;
        }

        @Override
        public void setAsText(final String text) throws IllegalArgumentException {
            T value = T.valueOf(typeParameterClass, text);
            setValue(value);
        }
    }
}
