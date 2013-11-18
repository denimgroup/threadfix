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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;

@Controller
@RequestMapping("/configuration/keys")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_API_KEYS')")
public class APIKeyController {

	private APIKeyService apiKeyService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(APIKeyController.class);

	@Autowired
	public APIKeyController(APIKeyService apiKeyService) {
		this.apiKeyService = apiKeyService;
	}

	public APIKeyController(){}
	
	@InitBinder
	public void initBinder(WebDataBinder dataBinder) {
		dataBinder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("note");
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(HttpServletRequest request, Model model) {
		model.addAttribute("apiKeyList", apiKeyService.loadAll());
		model.addAttribute("apiKey", new APIKey());

		return "config/keys/index";
	}

	@RequestMapping(value = "/new", method = RequestMethod.POST)
	public String newSubmit(HttpServletRequest request, @RequestParam String note,
			Model model) {
		
		boolean restricted = request.getParameter("isRestrictedKey") != null;
		
		APIKey newAPIKey = apiKeyService.createAPIKey(note, restricted);
		apiKeyService.storeAPIKey(newAPIKey);
		
		String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
		log.debug(currentUser + " has created an API key with the note " + note +
				", and the ID " + newAPIKey.getId());
		
		return keyTable(model, "API key was successfully created.");
	}
	
	@RequestMapping(value = "/{keyId}/delete", method = RequestMethod.POST)
	public String delete(@PathVariable("keyId") int keyId, Model model,
			HttpServletRequest request) {
		APIKey newAPIKey = apiKeyService.loadAPIKey(keyId);
		
		if (newAPIKey != null) {
			apiKeyService.deactivateApiKey(newAPIKey);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("API Key", keyId));
			throw new ResourceNotFoundException();
		}
		
		return keyTable(model, "API key was successfully deleted.");
	}
	
	@RequestMapping(value = "/{keyId}/edit", method = RequestMethod.POST)
	public String saveEdit(HttpServletRequest request, Model model,
			@PathVariable("keyId") int keyId, @RequestParam String note) {
		APIKey apiKey = apiKeyService.loadAPIKey(keyId);
		
		boolean restricted = request.getParameter("isRestrictedKey") != null;
		
		if (note != null) {
			apiKey.setNote(note);
			apiKey.setIsRestrictedKey(restricted);
			apiKeyService.storeAPIKey(apiKey);
			
			return keyTable(model, "API key was successfully edited.");
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("API Key", keyId));
			throw new ResourceNotFoundException();
		}
	}
	
	private String keyTable(Model model, String message) {
		model.addAttribute("contentPage", "config/keys/keyTable.jsp");
		model.addAttribute("apiKeyList", apiKeyService.loadAll());
		model.addAttribute("apiKey", new APIKey());
		model.addAttribute("successMessage", message);
		return "ajaxSuccessHarness";
	}
}
