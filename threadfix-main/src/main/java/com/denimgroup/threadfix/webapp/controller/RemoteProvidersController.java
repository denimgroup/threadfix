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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.data.enums.QualysPlatform;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService.ResponseCode;
import com.denimgroup.threadfix.service.ScheduledRemoteProviderImportService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

@Controller
@RequestMapping("configuration/remoteproviders")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
@SessionAttributes({"remoteProviderType", "remoteProviderApplication"})
public class RemoteProvidersController {

	private final SanitizedLogger log = new SanitizedLogger(RemoteProvidersController.class);

    @Autowired
    private RemoteProviderTypeService remoteProviderTypeService;
    @Autowired
    private RemoteProviderApplicationService remoteProviderApplicationService;
    @Autowired
	private OrganizationService organizationService;
    @Autowired
    ScheduledRemoteProviderImportService scheduledRemoteProviderImportService;

    @InitBinder
    public void setAllowedFields(WebDataBinder dataBinder) {
        dataBinder.setAllowedFields("apiKey", "username", "password", "application.id",
                "application.organization.id", "platform");
    }

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		log.debug("Processing request for Remote Provider index.");
		List<RemoteProviderType> typeList = remoteProviderTypeService.loadAll();

		for (RemoteProviderType type : typeList) {
			if (type != null && type.getApiKey() != null) {
				type.setApiKey(mask(type.getApiKey()));
			}
		}

		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));
		PermissionUtils.filterApps(typeList);

		model.addAttribute("remoteProviders", typeList);
		model.addAttribute("remoteProviderType", new RemoteProviderType());
		model.addAttribute("remoteProviderApplication", new RemoteProviderApplication());
		model.addAttribute("organizationList", organizationService.loadAllActiveFilter());

        PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_REMOTE_PROVIDERS, Permission.CAN_UPLOAD_SCANS);
		return "config/remoteproviders/index";
	}

	private String mask(String input) {
		if (input != null) {
			if (input.length() > 5) {
                return input.replace(input.substring(0,input.length() - 4),
                        RemoteProviderTypeService.API_KEY_PREFIX);
			} else {
				// should never get here, but let's not return the info anyway
				return RemoteProviderTypeService.API_KEY_PREFIX;
			}
		} else {
			return null;
		}
	}
	
	@RequestMapping(value="/{typeId}/update", method = RequestMethod.GET)
	public @ResponseBody RestResponse<List<RemoteProviderApplication>> updateApps(@PathVariable("typeId") int typeId) {
		log.info("Processing request for RemoteProviderType update.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);

        if (remoteProviderType == null) {
            return RestResponse.failure("The requested Remote Provider type was not found.");
        } else {
            List<RemoteProviderApplication> returnApps = remoteProviderApplicationService.updateApplications(remoteProviderType);
            remoteProviderTypeService.store(remoteProviderType);

            return RestResponse.success(returnApps);
        }
    }
	
	@RequestMapping(value="/{typeId}/importAll", method = RequestMethod.GET)
	public @ResponseBody RestResponse<String> importAllScans(@PathVariable("typeId") int typeId) {
		log.info("Processing request for RemoteProviderType bulk import.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		
		remoteProviderApplicationService.addBulkImportToQueue(remoteProviderType);
		
		return RestResponse.success("Importing scans.");
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/import", method = RequestMethod.GET)
	public @ResponseBody RestResponse<String> importScan(@PathVariable("appId") int appId) {
		
		log.info("Processing request for scan import.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		if (remoteProviderApplication == null || remoteProviderApplication.getApplication() == null) {
			return RestResponse.failure("The requested application wasn't found.");
		}
		
		if (remoteProviderApplication.getApplication().getId() == null ||
				remoteProviderApplication.getApplication().getOrganization() == null ||
				remoteProviderApplication.getApplication().getOrganization().getId() == null ||
				!PermissionUtils.isAuthorized(Permission.CAN_UPLOAD_SCANS,
						remoteProviderApplication.getApplication().getOrganization().getId(),
						remoteProviderApplication.getApplication().getId())) {
            return RestResponse.failure("You don't have permission to do that.");
		}
		
		remoteProviderTypeService.decryptCredentials(
				remoteProviderApplication.getRemoteProviderType());
		
		ResponseCode response = remoteProviderTypeService.importScansForApplication(remoteProviderApplication);
		
		if (response.equals(ResponseCode.SUCCESS)) {
            return RestResponse.success("Do the redirect");
		} else {
			String errorMsg;
			if (response.equals(ResponseCode.ERROR_NO_SCANS_FOUND)) {
				errorMsg = "No scans were found for this Remote Provider application.";
			} else if (response.equals(ResponseCode.ERROR_NO_NEW_SCANS)) {
				errorMsg = "Application already imported scans from this Remote Provider, no newer scans were found. You have to delete old scans before adding new ones.";
			} else {
				errorMsg = "Error when trying to import scans.";
			}
			
			return RestResponse.failure(errorMsg);
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{remoteProviderApplicationId}/edit", method = RequestMethod.POST)
	public @ResponseBody RestResponse<RemoteProviderApplication> configureAppSubmit(
            @PathVariable int typeId,
            @PathVariable int remoteProviderApplicationId,
            @RequestParam int applicationId) {

        String errMsg = remoteProviderApplicationService.processApp(remoteProviderApplicationId, applicationId);

        if (errMsg != null && !errMsg.isEmpty()) {
            return RestResponse.failure(errMsg);
        }

		return RestResponse.success(remoteProviderApplicationService.load(remoteProviderApplicationId));
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{remoteProviderApplicationId}/setName", method = RequestMethod.POST)
	public @ResponseBody RestResponse<RemoteProviderApplication> configureApplicationName(
            @PathVariable int remoteProviderApplicationId,
            @RequestParam String customName) {

        String errMsg = remoteProviderApplicationService.setCustomName(remoteProviderApplicationId, customName);

        if (errMsg != null && !errMsg.isEmpty() && !errMsg.equals("Success")) {
            return RestResponse.failure(errMsg);
        }

		return RestResponse.success(remoteProviderApplicationService.load(remoteProviderApplicationId));
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{rpAppId}/delete/{appId}", method = RequestMethod.POST)
	public @ResponseBody RestResponse<RemoteProviderApplication> deleteAppConfiguration(@PathVariable("typeId") int typeId, @PathVariable("rpAppId") int rpAppId,
			@PathVariable("appId") int appId) {
        RemoteProviderApplication dbRemoteProviderApplication =
                remoteProviderApplicationService.load(rpAppId);

        remoteProviderApplicationService.deleteMapping(dbRemoteProviderApplication, appId);

        return RestResponse.success(dbRemoteProviderApplication);
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.POST)
	public @ResponseBody Object configureFinish(@PathVariable("typeId") int typeId,
			HttpServletRequest request) {
		
		ResponseCode test = remoteProviderTypeService.checkConfiguration(
				request.getParameter("username"),
				request.getParameter("password"),
				request.getParameter("apiKey"),
                request.getParameter("matchSourceNumbers"),
                request.getParameter("platform"),
                getAuthenticationFieldMap(request),
                typeId);

		if (test.equals(ResponseCode.BAD_ID)) {
			return RestResponse.failure("Unable to find that Remote Provider Type.");
		} else if (test.equals(ResponseCode.NO_APPS)) {

			String error = "We were unable to retrieve a list of applications using these credentials." +
					" Please ensure that the credentials are valid and that there are applications " +
					"available in the account.";
            log.error(error);
			return RestResponse.failure(error);
		} else if (test.equals(ResponseCode.SUCCESS)) {
            RemoteProviderType type = remoteProviderTypeService.load(typeId);
			return ControllerUtils.writeSuccessObjectWithView(type, AllViews.TableRow.class);
		} else {
            log.warn("Response code was not success but we're still returning success. This shouldn't happen.");
            return RestResponse.failure("Response was " + test);
		}
	}

    private Map<String, String> getAuthenticationFieldMap(HttpServletRequest request) {
        Map<String, String> authenticationFieldMap = newMap();

        for (int i = 0; i < 100; i++) {
            String value = request.getParameter("authenticationFields[" + i + "].value");
            String name = request.getParameter("authenticationFields[" + i + "].name");
            if (value != null && name != null) {
                authenticationFieldMap.put(name, value);
            }
        }

        return authenticationFieldMap;
    }

    @PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/clearConfiguration", method = RequestMethod.POST)
	public @ResponseBody RestResponse<RemoteProviderType> clearConfiguration(@PathVariable("typeId") int typeId,
			HttpServletRequest request) {
		
		RemoteProviderType type = remoteProviderTypeService.load(typeId);
		
		if (type != null) {
			remoteProviderTypeService.clearConfiguration(typeId);
			ControllerUtils.addSuccessMessage(request, type.getName() + " configuration was cleared successfully.");
            return RestResponse.success(remoteProviderTypeService.load(typeId));
		} else {
            return RestResponse.failure("Unable to find that Remote Provider Type");
        }
	}

	@RequestMapping(value="/getMap", method = RequestMethod.GET)
	public @ResponseBody Object list() {

        Map<String, Object> map = new HashMap<>();

        map.put("remoteProviders", remoteProviderTypeService.loadAll());
        map.put("qualysPlatforms", QualysPlatform.getPlatforms());
        map.put("teams", organizationService.loadAllActive());
        map.put("scheduledImports", scheduledRemoteProviderImportService.loadAll());

		return ControllerUtils.writeSuccessObjectWithView(map, AllViews.TableRow.class);
	}
}
