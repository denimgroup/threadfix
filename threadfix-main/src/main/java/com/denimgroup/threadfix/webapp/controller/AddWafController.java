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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/wafs/new")
@SessionAttributes("waf")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
public class AddWafController {
	
	public AddWafController(){}

    @Autowired
	private WafService wafService = null;
    @Autowired
	private ApplicationService applicationService = null;

	private final SanitizedLogger log = new SanitizedLogger(AddWafController.class);

	@ModelAttribute
	public List<WafType> populateWafTypes() {
		return wafService.loadAllWafTypes();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String newForm(Model model) {
		Waf waf = new Waf();
		model.addAttribute(waf);
		return "wafs/form";
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "wafType.id", "applicationId");
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value="/ajax/appPage", method = RequestMethod.POST)
	public Object newSubmitAjaxAppPage(@Valid @ModelAttribute Waf waf,
								BindingResult result,
								SessionStatus status, Model model,
								HttpServletRequest request) {
		model.addAttribute("createWafUrl", "/wafs/new/ajax/appPage");

		String validationResult = newSubmit(waf,result,status,model,request);
		
		if (!validationResult.equals("SUCCESS")) {
			return FormRestResponse.failure(validationResult, result);
		}
		
		Application application = null;
		if (request.getParameter("applicationId") != null) {
			try {
                Integer testId = Integer.valueOf(request.getParameter("applicationId"));
				application = applicationService.loadApplication(testId);
			} catch (NumberFormatException e) {
				log.warn("Non-numeric value discovered in applicationId field. Someone is trying to tamper with it.");
			}
		}
		
		if (application != null) {
            // remove any outdated vuln -> waf rule links
            applicationService.updateWafRules(application, 0);
			application.setWaf(waf);
			applicationService.storeApplication(application, EventAction.APPLICATION_EDIT);
		}

        return RestResponse.success(waf);
	}
	
	@RequestMapping(value="/ajax", method = RequestMethod.POST)
	public String newSubmitAjax(@Valid @ModelAttribute Waf waf, 
			BindingResult result,
			SessionStatus status, Model model,
			HttpServletRequest request) {
		model.addAttribute("createWafUrl", "/wafs/new/ajax");

		String validationResult = newSubmit(waf,result,status,model,request);
		
		if (!validationResult.equals("SUCCESS")) {
			return validationResult;
		}
		
		model.addAttribute("successMessage", "WAF " + waf.getName() + " was successfully created.");
		model.addAttribute("contentPage", "wafs/wafsTable.jsp");
		
		return "ajaxSuccessHarness";
	}
	
	public String newSubmit(@Valid @ModelAttribute Waf waf, 
			BindingResult result,
			SessionStatus status, Model model,
			HttpServletRequest request) {
		if (result.hasErrors()) {
			model.addAttribute("contentPage", "wafs/forms/createWafForm.jsp");
			return "ajaxFailureHarness";
		} else {
			if (waf.getName().trim().equals("")) {
				result.rejectValue("name", null, null, "This field cannot be blank");
			} else {
				Waf databaseWaf = wafService.loadWaf(waf.getName().trim());
				if (databaseWaf != null) {
					result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
				}
			}
			
			if (waf.getWafType() == null) {
				result.rejectValue("wafType.id", MessageConstants.ERROR_REQUIRED, new String [] { "WAF Type" }, null );
            } else if (wafService.loadWafType(waf.getWafType().getId()) == null) {
				result.rejectValue("wafType.id", MessageConstants.ERROR_INVALID, new String [] { waf.getWafType().getId().toString() }, null );
            } else {
				waf.setWafType(wafService.loadWafType(waf.getWafType().getId()));
            }

			if (result.hasErrors()) {
				model.addAttribute("contentPage", "wafs/forms/createWafForm.jsp");
				return "ajaxFailureHarness";
			}
			
			wafService.storeWaf(waf);
			
			String currentUser = SecurityContextHolder.getContext().getAuthentication().getName();
			log.debug(currentUser + " has created a WAF with the name " + waf.getName() + 
					", the type " + waf.getWafType().getName() + 
					" and ID " + waf.getId() + ".");
			
			model.addAttribute(wafService.loadAll());
			model.addAttribute("newWaf", new Waf());
			model.addAttribute("waf", new Waf());
			model.addAttribute("wafPage", true);
            PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_WAFS);

			return "SUCCESS";
		}
	}
}
