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

import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/configuration/defecttrackers/new")
@SessionAttributes("defectTracker")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class AddDefectTrackerController {

    @Autowired
	private DefectTrackerService defectTrackerService;

	public AddDefectTrackerController(){}

	private static final SanitizedLogger log = new SanitizedLogger(AddDefectTrackerController.class);

	@InitBinder
	public void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTrackerType.id");
	}

	@ModelAttribute
	public List<DefectTrackerType> populateDefectTrackerTypes() {
		return defectTrackerService.loadAllDefectTrackerTypes();
	}

	@RequestMapping(method = RequestMethod.GET)
	public String setup(Model model) {
		DefectTracker defectTracker = new DefectTracker();
		model.addAttribute(defectTracker);
		return "config/defecttrackers/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public @ResponseBody Object processSubmit(@Valid @ModelAttribute DefectTracker defectTracker,
			BindingResult result, Model model) {

        if (!PermissionUtils.hasGlobalPermission(Permission.CAN_MANAGE_DEFECT_TRACKERS)) {
            return RestResponse.failure("You do not have permission to do that.");
        }

		if (defectTracker.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		}
		
		if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.",result);
		} else {
			
			DefectTracker databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTracker.getName().trim());
			if (databaseDefectTracker != null)
				result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);

			if (defectTracker.getDefectTrackerType() == null) {
				result.rejectValue("defectTrackerType.id", MessageConstants.ERROR_INVALID,
						new String [] { "Defect Tracker Type" }, null );
			} else if (defectTrackerService.loadDefectTrackerType(defectTracker.getDefectTrackerType().getId()) == null) {
				result.rejectValue("defectTrackerType.id", MessageConstants.ERROR_INVALID,
						new String [] { defectTracker.getDefectTrackerType().getId().toString() }, null );
			} else if (!defectTrackerService.checkUrl(defectTracker, result)) {
                if (!result.hasFieldErrors("url")) {
                    result.rejectValue("url", MessageConstants.ERROR_INVALID, new String [] { "URL" },
							"URL is not associated with selected defect tracker.");
                } else if (result.getFieldError("url").getDefaultMessage() != null &&
                        result.getFieldError("url").getDefaultMessage().equals(
                                AbstractDefectTracker.INVALID_CERTIFICATE) ){
                    result.rejectValue("url", null, null, MessageConstants.ERROR_SELF_CERTIFICATE);
                }
            }
			
			if (result.hasErrors()) {
                return FormRestResponse.failure("Found some errors.",result);
			}

            defectTracker.setDefectTrackerType(defectTrackerService.loadDefectTrackerType(defectTracker.getDefectTrackerType().getId()));
			defectTrackerService.storeDefectTracker(defectTracker);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();
			log.info(user + " has successfully created a Defect Tracker with the name " + defectTracker.getName() +
					", the URL " + defectTracker.getUrl() + 
					", the type " + defectTracker.getDefectTrackerType().getName() + 
					", and the ID " + defectTracker.getId());

            model.addAttribute("defectTracker", new DefectTracker());

            return RestResponse.success(defectTracker);
        }
	}
}
