package com.denimgroup.threadfix.webapp.controller;

import javax.validation.Valid;

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
		if (defaultDefectProfile.getReferenceApplication() == null ||
				applicationService.loadApplication(defaultDefectProfile.getReferenceApplication().getId()) == null) {
			result.rejectValue("referenceApplication.id", null, null, "Reference Application is invalid.");
		}

		defaultDefectProfileService.validateName(defaultDefectProfile, result);

		if (result.hasErrors()) {
			return FormRestResponse.failure("Found some errors.",result);
		}

		defaultDefectProfile.setReferenceApplication(applicationService.loadApplication(defaultDefectProfile.getReferenceApplication().getId()));
		defaultDefectProfile.setDefectTracker(defectTrackerService.loadDefectTracker(defaultDefectProfile.getDefectTracker().getId()));
		defaultDefectProfileService.storeDefaultDefectProfile(defaultDefectProfile);

		return RestResponse.success(defaultDefectProfile);
	}
}
