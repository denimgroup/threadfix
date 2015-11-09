package com.denimgroup.threadfix.webapp.controller;

import javax.validation.Valid;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;

import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefaultDefectProfileService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.fasterxml.jackson.annotation.JsonView;

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
