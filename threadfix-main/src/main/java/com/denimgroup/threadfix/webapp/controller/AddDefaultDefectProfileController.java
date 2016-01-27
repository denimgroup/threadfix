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
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefaultDefectProfileService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Controller
@RequestMapping("/default/addProfile")
public class AddDefaultDefectProfileController {

	private final SanitizedLogger log = new SanitizedLogger(AddDefaultDefectProfileController.class);

	@Autowired
	private DefaultDefectProfileService defaultDefectProfileService;
	@Autowired
	private DefectTrackerService defectTrackerService;
	@Autowired
	private ApplicationService applicationService;

	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("id", "name", "defectTracker.id", "referenceApplication.id");
	}

	@JsonView(AllViews.DefectTrackerInfos.class)
	@RequestMapping(method = RequestMethod.POST)
	public @ResponseBody RestResponse<DefaultDefectProfile> createNewDefaultDefectProfile(@Valid @ModelAttribute DefaultDefectProfile defaultDefectProfile,
			BindingResult result) {

		if (defaultDefectProfile.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}

		if (defaultDefectProfile.getDefectTracker() == null ||
				defectTrackerService.loadDefectTracker(defaultDefectProfile.getDefectTracker().getId()) == null) {
			return FormRestResponse.failure("Defect Tracker is invalid.",result);
		}

		Application referenceApplication = null;
		if (defaultDefectProfile.getReferenceApplication() != null) {
			referenceApplication = applicationService.loadApplication(defaultDefectProfile.getReferenceApplication().getId());
		}
		DefectTracker defectTracker = null;
		if (defaultDefectProfile.getDefectTracker() != null) {
			defectTracker = defectTrackerService.loadDefectTracker(defaultDefectProfile.getDefectTracker().getId());
		}
		if ((referenceApplication == null) &&
				((defectTracker.getEncryptedDefaultPassword() == null) ||
						(defectTracker.getEncryptedDefaultUsername() == null))){
			result.rejectValue("referenceApplication.id", null, null, "Reference Application is invalid or Defect Tracker does not have default credentials.");
		} else if (referenceApplication == null && (defectTracker.getDefaultProductName() == null || defectTracker.getDefaultProductName().isEmpty())) {
			result.rejectValue("referenceApplication.id", null, null, "Defect Tracker does not have default product.");
		} else if (referenceApplication != null && (referenceApplication.getProjectName() == null)) {
			result.rejectValue("referenceApplication.id", null, null, "Application does not link to any Defect Tracker product.");
		}

		defaultDefectProfileService.validateName(defaultDefectProfile, result);

		if (result.hasErrors()) {
			return FormRestResponse.failure("Found some errors.",result);
		}

		log.info("Creating new Defect Profile with name " + defaultDefectProfile.getName());

		defaultDefectProfile.setReferenceApplication(referenceApplication);
		defaultDefectProfile.setDefectTracker(defectTracker);
		defaultDefectProfileService.storeDefaultDefectProfile(defaultDefectProfile);

		return RestResponse.success(defaultDefectProfile);
	}
}
