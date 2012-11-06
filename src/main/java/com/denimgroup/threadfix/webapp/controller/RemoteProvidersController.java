////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.RemoteProviderApplicationService;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
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
		dataBinder.setAllowedFields(new String[] { "apiKey", "username", 
				"password", "application.id", "application.organization.id", "isEuropean" });
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
		
		Object message = null;
		if (request != null && request.getSession() != null) {
			message = request.getSession().getAttribute("error");
			if (message != null) {
				request.getSession().removeAttribute("error");
			}
		}

		model.addAttribute("message", message);
		model.addAttribute("remoteProviders", typeList);
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
	public String updateApps(@PathVariable("typeId") int typeId) {
		log.info("Processing request for RemoteProviderType update.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		remoteProviderApplicationService.updateApplications(remoteProviderType);
		remoteProviderTypeService.store(remoteProviderType);
		
		return "redirect:/configuration/remoteproviders/";
	}
	
	@RequestMapping(value="/{typeId}/apps/{appId}/import", method = RequestMethod.GET)
	public String importScan(@PathVariable("typeId") int typeId, 
			HttpServletRequest request, @PathVariable("appId") int appId) {
		log.info("Processing request for scan import.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		if (remoteProviderApplication == null || remoteProviderApplication.getApplication() == null) {
			request.getSession().setAttribute("error", 
					"The scan request failed because it could not find the requested application.");

			return "redirect:/configuration/remoteproviders/";
		}
		
		if (remoteProviderApplication != null) {
			remoteProviderTypeService.decryptCredentials(
					remoteProviderApplication.getRemoteProviderType());
		}
		
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		if (remoteProviderApplicationService.importScansForApplication(remoteProviderApplication)) {
			return "redirect:/organizations/" + 
						remoteProviderApplication.getApplication().getOrganization().getId() + 
						"/applications/" +
						remoteProviderApplication.getApplication().getId();
		} else {
			request.getSession().setAttribute("error", "No new scans were found.");
			return "redirect:/configuration/remoteproviders/";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.GET)
	public ModelAndView configureAppForm(@PathVariable("typeId") int typeId,
			@PathVariable("appId") int appId) {
		log.info("Processing request for Edit App page.");
		RemoteProviderApplication remoteProviderApplication = remoteProviderApplicationService.load(appId);
		
		ModelAndView modelAndView = new ModelAndView("config/remoteproviders/edit");
		modelAndView.addObject("remoteProviderApplication", remoteProviderApplication);
		modelAndView.addObject("organizationList", organizationService.loadAllActive());
		return modelAndView;
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/apps/{appId}/edit", method = RequestMethod.POST)
	public String configureAppSubmit(@PathVariable("typeId") int typeId,
			@Valid @ModelAttribute RemoteProviderApplication remoteProviderApplication, 
			BindingResult result, SessionStatus status,
			Model model) {
		if (result.hasErrors() || remoteProviderApplication.getApplication() == null) {
			return "config/remoteproviders/edit";
		} else {
			remoteProviderApplicationService.processApp(result, remoteProviderApplication);
			
			if (result.hasErrors()) {
				model.addAttribute("remoteProviderApplication",remoteProviderApplication);
				model.addAttribute("organizationList", organizationService.loadAllActive());
				return "config/remoteproviders/edit";
			}

			status.setComplete();
			return "redirect:/configuration/remoteproviders";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.GET)
	public ModelAndView configureStart(@PathVariable("typeId") int typeId) {
		log.info("Processing request for Remote Provider config page.");
		RemoteProviderType remoteProviderType = remoteProviderTypeService.load(typeId);
		 
		if (remoteProviderType.getPassword() != null) {
			// This will prevent actual password data being sent to the page
			remoteProviderType.setPassword(RemoteProviderTypeService.USE_OLD_PASSWORD);
		}
		if (remoteProviderType.getApiKey() != null) {
			remoteProviderType.setApiKey(mask(remoteProviderType.getApiKey()));
		}
		
		boolean isQualys = remoteProviderType.getName() != null && 
				remoteProviderType.getName().equals(RemoteProviderType.QUALYSGUARD_WAS);
		
		ModelAndView modelAndView = new ModelAndView("config/remoteproviders/configure");
		modelAndView.addObject(remoteProviderType);
		modelAndView.addObject("isQualys",isQualys);
		return modelAndView;
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/configure", method = RequestMethod.POST)
	public String configureFinish(@PathVariable("typeId") int typeId,
			@Valid @ModelAttribute RemoteProviderType remoteProviderType, 
			BindingResult result, SessionStatus status, Model model) {
		if (result.hasErrors()) {
			return "config/remoteproviders/configure";
		} else {
			remoteProviderTypeService.checkConfiguration(remoteProviderType, 
					result, typeId);
			
			if (result.hasErrors()) {
				boolean isQualys = remoteProviderType.getName() != null && 
						remoteProviderType.getName().equals(RemoteProviderType.QUALYSGUARD_WAS);
				model.addAttribute("isQualys", isQualys);
				return "config/remoteproviders/configure";
			}
			
			status.setComplete();
			return "redirect:/configuration/remoteproviders";
		}
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_REMOTE_PROVIDERS')")
	@RequestMapping(value="/{typeId}/clearConfiguration", method = RequestMethod.POST)
	public String clearConfiguration(@PathVariable("typeId") int typeId) {

		remoteProviderTypeService.clearConfiguration(typeId);
		return "redirect:/configuration/remoteproviders";
	}
}
