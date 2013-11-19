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
import org.springframework.security.core.context.SecurityContextHolder;
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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.service.PermissionService;
import com.denimgroup.threadfix.service.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs/{wafId}/edit")
@SessionAttributes("waf")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
public class EditWafController {
	
	public EditWafController(){}

	private WafService wafService = null;
	private PermissionService permissionService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "wafType.id");
	}
	
	@Autowired
	public EditWafController(WafService wafService,
			PermissionService permissionService) {
		this.wafService = wafService;
		this.permissionService = permissionService;
	}

	@ModelAttribute
	public List<WafType> populateWafTypes() {
		return wafService.loadAllWafTypes();
	}
	
	@RequestMapping(value="ajax", method = RequestMethod.POST)
	public String editSubmitFromTable(@PathVariable("wafId") int wafId, @Valid @ModelAttribute Waf waf,
			BindingResult result, SessionStatus status, Model model) {
		
		String editResult = editSubmit(wafId, waf, result, status, model);
		
		if (editResult.equals("Success")) {
			return index(model, "The WAF " + waf.getName() + " has been successfully edited.");
		} else {
			return editResult;
		}
	}
	
	@RequestMapping(value="detail/ajax", method = RequestMethod.POST)
	public String editSubmitFromDetail(@PathVariable("wafId") int wafId, @Valid @ModelAttribute Waf waf,
			BindingResult result, SessionStatus status, Model model, HttpServletRequest request) {
		String editResult = editSubmit(wafId, waf, result, status, model);
		
		if (editResult.equals("Success")) {
			ControllerUtils.addSuccessMessage(request, "This WAF has been successfully updated.");
			model.addAttribute("contentPage", "/wafs/" + wafId);
			return "ajaxRedirectHarness";
		} else {
			return editResult;
		}
	}
	
	public String editSubmit(int wafId, Waf waf,
			BindingResult result, SessionStatus status, Model model) {
		waf.setId(wafId);
		
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "wafs/forms/editWafForm.jsp");
			return "ajaxFailureHarness";
		} else {
			
			if (waf.getName().trim().equals("")) {
				result.rejectValue("name", null, null, "This field cannot be blank");
			} else {
				Waf databaseWaf = wafService.loadWaf(waf.getName().trim());
				if (databaseWaf != null && !databaseWaf.getId().equals(waf.getId())) {
					result.rejectValue("name", "errors.nameTaken");
				}
			}
			
			if (waf.getWafType() == null)
				result.rejectValue("wafType.id", "errors.required", new String [] { "WAF Type" }, null );
			else if (wafService.loadWafType(waf.getWafType().getId()) == null)
				result.rejectValue("wafType.id", "errors.invalid", new String [] { waf.getWafType().getId().toString() }, null );
			
			if (result.hasErrors()) {
				model.addAttribute("contentPage", "wafs/forms/editWafForm.jsp");
				return "ajaxFailureHarness";
			}
			
			wafService.storeWaf(waf);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug("The Waf " + waf.getName() + " (id=" + waf.getId() + ") has been edited by user " + currentUser);
			
			return "Success";
		}
	}
	
	private String index(Model model, String successMessage) {
		model.addAttribute(wafService.loadAll());
		model.addAttribute("newWaf", new Waf());
		model.addAttribute("waf", new Waf());
		model.addAttribute("wafPage", true);
		model.addAttribute("successMessage", successMessage);
		permissionService.addPermissions(model, null, null, Permission.CAN_MANAGE_WAFS);
		model.addAttribute("contentPage", "wafs/wafsTable.jsp");
		return "ajaxSuccessHarness";
	}
}
