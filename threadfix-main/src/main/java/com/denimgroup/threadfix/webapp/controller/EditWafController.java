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

import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.WafService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/wafs/{wafId}/edit")
@SessionAttributes("waf")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
public class EditWafController {
	
    @Autowired
	private WafService wafService = null;

	private final SanitizedLogger log = new SanitizedLogger(EditUserController.class);

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "wafType.id");
	}

	@ModelAttribute
	public List<WafType> populateWafTypes() {
		return wafService.loadAllWafTypes();
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(method = RequestMethod.POST)
	@ResponseBody
	public Object editSubmitFromTable(@PathVariable("wafId") int wafId, @Valid @ModelAttribute Waf waf,
			BindingResult result, SessionStatus status, Model model) {
		
		String editResult = editSubmit(wafId, waf, result, status, model);
		
		if (editResult.equals("Success")) {
			return RestResponse.success(wafService.loadAll());
		} else {
			return FormRestResponse.failure(editResult, result);
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
					result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
				}
			}
			
			if (waf.getWafType() == null)
				result.rejectValue("wafType.id", MessageConstants.ERROR_REQUIRED, new String [] { "WAF Type" }, null );
			else if (wafService.loadWafType(waf.getWafType().getId()) == null)
				result.rejectValue("wafType.id", MessageConstants.ERROR_INVALID, new String [] { waf.getWafType().getId().toString() }, null );
			
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
}
