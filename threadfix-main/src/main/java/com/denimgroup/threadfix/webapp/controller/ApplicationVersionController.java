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

import com.denimgroup.threadfix.data.entities.ApplicationVersion;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationVersionService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Date;

@Controller
@RequestMapping("/organizations/{orgId}/applications/")
public class ApplicationVersionController {

	@Autowired
	private ApplicationVersionService applicationVersionService;
	private final SanitizedLogger log = new SanitizedLogger(ApplicationVersionController.class);

	// Turn Date.getTime() javascript numbers into java.util.Date objects.
	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.registerCustomEditor(Date.class, new NumericDatePropertyEditorSupport());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "date", "id");
	}
	
	@RequestMapping(value = "{appId}/version/new", method = RequestMethod.POST)
	public @ResponseBody Object newSubmit(HttpServletRequest request,
										  @PathVariable("orgId") int orgId,
										  @PathVariable("appId") int appId,
										  @Valid @ModelAttribute ApplicationVersion applicationVersion,
										  BindingResult result) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			RestResponse.failure("You don't have permission to manage application.");
		}

		log.info("Got a request to save new application version. About to validate.");
		// Input validation
		applicationVersionService.validate(applicationVersion, result, appId);

		if (result.hasErrors()) {
			return FormRestResponse.failure("Errors", result);
		}
		log.info("Saving version " + applicationVersion.getName() + " of application " + applicationVersion.getApplication().getName());
		applicationVersionService.storeVersion(applicationVersion);

		return RestResponse.success(applicationVersion);
	}


	@RequestMapping(value = "{appId}/version/{versionId}/delete", method = RequestMethod.POST)
	@ResponseBody
	public RestResponse<String> delete(@PathVariable("orgId") int orgId,
									   @PathVariable("appId") int appId,
									   @PathVariable("versionId") int versionId) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			RestResponse.failure("You don't have permission to manage application.");
		}
		log.info("Got a request to remove application version with Id " + versionId);

		ApplicationVersion version = applicationVersionService.loadVersion(versionId);

		if (version != null) {
			if (version.getApplication().getId() != appId) {
				RestResponse.failure("Application is invalid.");
			}
			applicationVersionService.delete(version);
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("Application Version", versionId));
			throw new ResourceNotFoundException();
		}

		return RestResponse.success("Version was successfully deleted.");
	}
	
	@RequestMapping(value = "{appId}/version/{versionId}/edit", method = RequestMethod.POST)
	public @ResponseBody Object saveEdit(HttpServletRequest request,
													   @PathVariable("orgId") int orgId,
													   @PathVariable("appId") int appId,
													   @PathVariable("versionId") int versionId,
													   @Valid @ModelAttribute ApplicationVersion applicationVersion,
													   BindingResult result) {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)) {
			RestResponse.failure("You don't have permission to manage application.");
		}
		log.info("Got a request to edit application version. About to validate.");
		applicationVersionService.validate(applicationVersion, result, appId);

		if (result.hasErrors()) {
			return FormRestResponse.failure("Errors", result);
		}
		log.info("Editing version " + applicationVersion.getName() + " of application " + applicationVersion.getApplication().getName());
		applicationVersionService.storeVersion(applicationVersion);

		return RestResponse.success(applicationVersion);

	}

}
