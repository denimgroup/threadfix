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

import javax.servlet.http.HttpServletRequest;

import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.service.ScanParametersService;
import com.denimgroup.threadfix.service.beans.ScanParametersBean;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/setParameters")
@SessionAttributes("scanParametersBean")
public class ScanParametersController {
	
	@Autowired ScanParametersService scanParametersService;

	@RequestMapping(method = RequestMethod.POST)
	public String setScanParameters(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			HttpServletRequest request,
			@ModelAttribute ScanParametersBean scanParametersBean,
			BindingResult result,
			SessionStatus status,
			Model model) {
		
		scanParametersService.saveConfiguration(appId, scanParametersBean);
		
		ControllerUtils.addSuccessMessage(request, "Scan configuration was saved correctly.");
		
		status.setComplete();
		model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
		return "ajaxRedirectHarness";
	}
}
