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
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/configuration/defecttrackers/{defectTrackerId}/edit")
@SessionAttributes({"defectTracker", "editDefectTracker"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class EditDefectTrackerController {

    @Autowired
	private DefectTrackerService defectTrackerService;
	@Autowired
    private DefectService defectService;

	private final Log log = LogFactory.getLog(DefectTrackersController.class);

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}
	
	@InitBinder
	public void setAllowedFields(WebDataBinder dataBinder) {
		dataBinder.setAllowedFields("name", "url", "defectTrackerType.id", "defaultUsername", "defaultPassword", "defaultProductName");
	}

	@ModelAttribute
	public List<DefectTrackerType> populateDefectTrackerTypes() {
		return defectTrackerService.loadAllDefectTrackerTypes();
	}

	@RequestMapping(method = RequestMethod.POST)
	@ResponseBody
	@JsonView(AllViews.DefectTrackerInfos.class)
	public RestResponse<DefectTracker> processSubmitAjax(
            @PathVariable("defectTrackerId") int defectTrackerId,
			@Valid @ModelAttribute DefectTracker defectTracker,
            BindingResult result) {

        if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.",result);
        }

		if (defectTracker == null || defectTracker.getName() == null ||
				defectTracker.getName().trim().equals("") && !result.hasFieldErrors("name")) {
			result.rejectValue("name", null, null, "This field cannot be blank");
		} else {
            DefectTracker sameNameTracker = defectTrackerService.loadDefectTracker(defectTracker.getName().trim());
			if (sameNameTracker != null && !sameNameTracker.getId().equals(defectTrackerId)) {
				result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
			} else if (!defectTrackerService.checkUrl(defectTracker, result)) {
				if (!result.hasFieldErrors("url")) {
					result.rejectValue("url", "URL is not associated with selected defect tracker.",
							"URL is not associated with selected defect tracker.");
				} else if (result.getFieldError("url").getDefaultMessage() != null &&
						result.getFieldError("url").getDefaultMessage().equals(
								AbstractDefectTracker.INVALID_CERTIFICATE)){
                    result.rejectValue("url", null, null, MessageConstants.ERROR_SELF_CERTIFICATE);
				}
			} else if((defectTracker.getDefaultUsername() != null || defectTracker.getDefaultPassword() != null)
                    && !defectTrackerService.checkCredentials(defectTracker, result)){
                if (!result.hasFieldErrors("defaultUsername")) {
                    result.rejectValue("defaultUsername", null, null, defectTracker.getDefectTrackerType().getName() + " Credentials are invalid.");
                }
            }
		}
		
		if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.",result);
		} else {
            DefectTracker databaseDefectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
			if (databaseDefectTracker != null && databaseDefectTracker.getDefectTrackerType() != null &&
					defectTracker != null && defectTracker.getDefectTrackerType() != null &&
					defectTracker.getDefectTrackerType().getId() != null &&
					!defectTracker.getDefectTrackerType().getId().equals(
							databaseDefectTracker.getDefectTrackerType().getId())) {
				defectService.deleteByDefectTrackerId(defectTrackerId);
			}

            defectTracker.getDefectTrackerType().setName(
                    defectTrackerService.loadDefectTrackerType(
                            defectTracker.getDefectTrackerType().getId()).getName());

            DefectTracker oldTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
            oldTracker.setName(defectTracker.getName());
            oldTracker.setUrl(defectTracker.getUrl());
            oldTracker.setDefectTrackerType(defectTracker.getDefectTrackerType());
            oldTracker.setDefaultUsername(defectTracker.getDefaultUsername());
            oldTracker.setDefaultPassword(defectTracker.getDefaultPassword());
            oldTracker.setDefaultProductName(defectTracker.getDefaultProductName());

			defectTrackerService.storeDefectTracker(oldTracker);
			
			String user = SecurityContextHolder.getContext().getAuthentication().getName();

            log.debug("The DefectTracker " + defectTracker.getName() + " (id=" + defectTracker.getId() + ") has been edited by user " + user);

            return RestResponse.success(oldTracker);
		}
	}
}
