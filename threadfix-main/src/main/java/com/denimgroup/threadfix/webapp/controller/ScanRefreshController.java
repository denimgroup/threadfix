////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.logging.SanitizedLogger;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/progress/{numScans}")
public class ScanRefreshController {
	
	public static final String SCANNER_TYPE_ERROR = "ThreadFix was unable to find a suitable " +
			"scanner type for the file. Please choose one from the list.";

	private ApplicationService applicationService;
	
	private final SanitizedLogger log = new SanitizedLogger(ScanRefreshController.class);

	@Autowired
	public ScanRefreshController(ApplicationService applicationService) {
		this.applicationService = applicationService;
	}
	
	public ScanRefreshController(){}

	@RequestMapping(method = RequestMethod.GET)
	public String uploadIndex(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId,
			@PathVariable("numScans") int numScans,
			Model model) {

		log.info("Hit scan refresh controller.");
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || !app.isActive()) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		} else if (app.getScans() != null && app.getScans().size() != numScans) {
			model.addAttribute("contentPage", "/organizations/" + orgId + " /applications/" + appId);
			return "ajaxRedirectHarness";
		} else {
			model.addAttribute("wait", "true");
			return "ajaxJSONHarness";
		}
	}
}
