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

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService.ResponseCode;
import com.denimgroup.threadfix.service.SanitizedLogger;

@Controller
@RequestMapping("configuration/remoteproviders")
@SessionAttributes(value= {"remoteProviderType", "remoteProviderApplication"})
public class RemoteProvidersController {
	
	public RemoteProvidersController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(RemoteProvidersController.class);
	
	private RemoteProviderTypeService remoteProviderTypeService;
	private PermissionService permissionService;
	private RemoteProviderApplicationService remoteProviderApplicationService;
	private OrganizationService organizationService;
	
	@Autowired
	public RemoteProvidersController(RemoteProviderTypeService remoteProviderTypeService,
			RemoteProviderApplicationService remoteProviderApplicationService,
			PermissionService permissionService, OrganizationService organizationService) {
		this.remoteProviderTypeService = remoteProviderTypeService;
		this.remoteProviderApplicationService = remoteProviderApplicationService;
		this.organizationService = organizationService;
		this.permissionService = permissionService;
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("apiKey", "username",
                "password", "application.id", "application.organization.id", "isEuropean");
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model, HttpServletRequest request) {
		log.info("Processing request for Remote Provider index.");
		List<RemoteProviderType> typeList = remoteProviderTypeService.loadAll();
		
		for (RemoteProviderType type : typeList) {
			if (type != null && type.getApiKey() != null) {
				type.setApiKey(mask(type.getApiKey()));
			}
		}

		model.addAttribute("successMessage", ControllerUtils.getSuccessMessage(request));
		model.addAttribute("errorMessage", ControllerUtils.getErrorMessage(request));
		permissionService.filterApps(typeList);
		
		model.addAttribute("remoteProviders", typeList);
		model.addAttribute("remoteProviderType", new RemoteProviderType());
		model.addAttribute("remoteProviderApplication", new RemoteProviderApplication());
		model.addAttribute("organizationList", organizationService.loadAllActiveFilter());
		
		permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_REMOTE_PROVIDERS);
		return "config/remoteproviders/index";
	}
	
	private String mask(String input) {
		if (input != null) {
			if (input.length() > 5) {
				String replaced = input.replace(input.substring(0,input.length() - 4),
						RemoteProviderTypeService.API_KEY_PREFIX);
				return replaced;
			} else {
				// should never get here, but let's not return the info anyway
				return RemoteProviderTypeService.API_KEY_PREFIX;
			}
		} else {
			return null;
		}
	}
	
	@RequestMapping(value="/{typeId}/update", method = RequestMethod.GET)
	public String updateApps(@PathVariable("typeId") int typeId, HttpServletRequest request) {
		log.info("Processing request for RemoteProviderType update.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		remoteProviderApplicationService.updateApplications(remoteProviderType);
		remoteProviderTypeService.store(remoteProviderType);
		
		ControllerUtils.addSuccessMessage(request, "ThreadFix updated applications from " +
				remoteProviderType + ".");
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/importAll", method = RequestMethod.GET)
	public String importAllScans(@PathVariable("typeId") int typeId, HttpServletRequest request) {
		log.info("Processing request for RemoteProviderType bulk import.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		
		remoteProviderApplicationService.addBulkImportToQueue(remoteProviderType);
		
		ControllerUtils.addSuccessMessage(request, "ThreadFix is importing scans from " + remoteProviderType +
			" in the background. It may take a few minutes to finish the process.");
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/import", method = RequestMethod.GET)
	public String importScan(@PathVariable("typeId") int typeId,
			HttpServletRequest request, @PathVariable("appId") int appId) {
		
		log.info("Processing request for scan import.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		if (remoteProviderApplication == null || remoteProviderApplication.getApplication() == null) {
			request.getSession().setAttribute("errorMessage",
					"The scan request failed because it could not find the requested application.");

			return "redirect:/configuration/remoteproviders/";
		}
		
		if (remoteProviderApplication.getApplication().getId() == null ||
				remoteProviderApplication.getApplication().getOrganization() == null ||
				remoteProviderApplication.getApplication().getOrganization().getId() == null ||
				!permissionService.isAuthorized(Permission.CAN_UPLOAD_SCANS,
						remoteProviderApplication.getApplication().getOrganization().getId(),
						remoteProviderApplication.getApplication().getId())) {
			return "403";
		}
		
		remoteProviderTypeService.decryptCredentials(
				remoteProviderApplication.getRemoteProviderType());
		
		ResponseCode response = remoteProviderTypeService.importScansForApplication(remoteProviderApplication);
		
		if (response.equals(ResponseCode.SUCCESS)) {
			return "redirect:/organizations/" +
						remoteProviderApplication.getApplication().getOrganization().getId() +
						"/applications/" +
						remoteProviderApplication.getApplication().getId();
		} else {
			String errorMsg = null;
			if (response.equals(ResponseCode.ERROR_NO_SCANS_FOUND)) {
				errorMsg = "No scans were found for this Remote Provider.";
			} else if (response.equals(ResponseCode.ERROR_NO_NEW_SCANS)) {
				errorMsg = "Application already imported scans from this Remote Provider, no newer scans were found. You have to delete old scans before adding new ones.";
			} else {
				errorMsg = "Error when trying to import scans.";
			}
			
			request.getSession().setAttribute("errorMessage", errorMsg);
			return "redirect:/configuration/remoteproviders/";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.POST)
	public String configureAppSubmit(@PathVariable("typeId") int typeId, @PathVariable("appId") int appId,
			@Valid @ModelAttribute RemoteProviderApplication remoteProviderApplication,
			BindingResult result, SessionStatus status,
			Model model, HttpServletRequest request) {
		if (result.hasErrors() || remoteProviderApplication.getApplication() == null) {
			return "config/remoteproviders/edit";
		} else {
			
			RemoteProviderApplication dbRemoteProviderApplication =
					remoteProviderApplicationService.load(appId);
			
			if (dbRemoteProviderApplication != null) {
				remoteProviderApplication.setId(appId);
				remoteProviderApplication.setRemoteProviderType(dbRemoteProviderApplication.getRemoteProviderType());
			}
			
			String errMsg = remoteProviderApplicationService.processApp(result, dbRemoteProviderApplication, remoteProviderApplication.getApplication());
			
			if (errMsg != null && !errMsg.isEmpty()) {
				model.addAttribute("errorMessage", errMsg);
				model.addAttribute("remoteProviderApplication",remoteProviderApplication);
				model.addAttribute("contentPage", "config/remoteproviders/editMapping.jsp");
				model.addAttribute("organizationList", organizationService.loadAllActiveFilter());
				return "ajaxFailureHarness";
			}

			ControllerUtils.addSuccessMessage(request, "Application successfully updated.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{rpAppId}/delete/{appId}")
	public String deleteAppConfiguration(@PathVariable("typeId") int typeId, @PathVariable("rpAppId") int rpAppId,
			@PathVariable("appId") int appId,
			@Valid @ModelAttribute RemoteProviderApplication remoteProviderApplication,
			BindingResult result, SessionStatus status,
			Model model, HttpServletRequest request) {
		if (result.hasErrors()) {
			return "config/remoteproviders/edit";
		} else {
						
			RemoteProviderApplication dbRemoteProviderApplication =
					remoteProviderApplicationService.load(rpAppId);
			
			String errMsg = remoteProviderApplicationService.deleteMapping(result, dbRemoteProviderApplication, appId);

			ControllerUtils.addSuccessMessage(request, "Application successfully deleted. " + errMsg);
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		}
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.POST)
	public String configureFinish(@PathVariable("typeId") int typeId,
			HttpServletRequest request, Model model) {
		
		ResponseCode test = remoteProviderTypeService.checkConfiguration(
				request.getParameter("username"),
				request.getParameter("password"),
				request.getParameter("apiKey"), typeId);
		
		if (test.equals(ResponseCode.BAD_ID)) {
			return "403";
		} else if (test.equals(ResponseCode.NO_APPS)) {
			
			String error = "We were unable to retrieve a list of applications using these credentials." +
					" Please ensure that the credentials are valid and that there are applications " +
					"available in the account.";
			model.addAttribute("errorMessage", error);
			model.addAttribute("remoteProviderType", remoteProviderTypeService.load(typeId));
			model.addAttribute("contentPage", "config/remoteproviders/configure.jsp");
			return "ajaxFailureHarness";
		} else if (test.equals(ResponseCode.SUCCESS)) {
			ControllerUtils.addSuccessMessage(request, "Applications successfully updated.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		} else {
			ControllerUtils.addErrorMessage(request, "An unidentified error occurred.");
			model.addAttribute("contentPage", "/configuration/remoteproviders");
			return "ajaxRedirectHarness";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/clearConfiguration", method = RequestMethod.POST)
	public String clearConfiguration(@PathVariable("typeId") int typeId,
			HttpServletRequest request) {
		
		RemoteProviderType type = remoteProviderTypeService.load(typeId);
		
		if (type != null) {
			remoteProviderTypeService.clearConfiguration(typeId);
			ControllerUtils.addSuccessMessage(request, type.getName() + " configuration was cleared successfully.");
		}

		return "redirect:/configuration/remoteproviders";
	}
	
	@RequestMapping(value="/{id}/table", method = RequestMethod.POST)
	public String paginate(@PathVariable("id") int rpAppId, @RequestBody TableSortBean bean,
			Model model) {
		
		log.info("Processing request for paginating Remote Application .");
		List<RemoteProviderType> typeList = remoteProviderTypeService.loadAll();
		permissionService.filterApps(typeList);
		for (RemoteProviderType rp : typeList) {
			if (rp.getId() == rpAppId) {
				int numApps = 0;
				
				if (rp.getFilteredApplications() != null) {
					numApps = rp.getFilteredApplications().size();
				} else {
					
				}
				
				int lastIndex = bean.getPage()*100>=numApps ? numApps : bean.getPage()*100;
				rp.setFilteredApplications(rp.getFilteredApplications().subList((bean.getPage()-1)*100, lastIndex));
				
				model.addAttribute("remoteProvider", rp);
				
				long numPages = numApps / 100;
				if (numApps % 100 == 0) {
					numPages -= 1;
				}
				model.addAttribute("numPages", numPages);
				model.addAttribute("numApps", numApps);
				
				if (bean.getPage() > numPages) {
					bean.setPage((int) (numPages + 1));
				}
				
				if (bean.getPage() < 1) {
					bean.setPage(1);
				}
				break;
			}
		}
		
		model.addAttribute("page", bean.getPage());
		model.addAttribute(Permission.CAN_MANAGE_REMOTE_PROVIDERS.getCamelCase(), true);
		model.addAttribute("organizationList", organizationService.loadAllActiveFilter());
		
		bean.setOpen(true);
		bean.setFalsePositive(false);
		bean.setHidden(false);
		
		
		return "config/remoteproviders/rpAppTable";
	}
}
