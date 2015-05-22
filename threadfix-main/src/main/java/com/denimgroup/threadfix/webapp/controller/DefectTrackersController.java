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
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.denimgroup.threadfix.service.DefectTrackerTypeService;
import com.denimgroup.threadfix.service.ScheduledDefectTrackerUpdateService;
import com.denimgroup.threadfix.service.defects.AbstractDefectTracker;
import com.denimgroup.threadfix.service.defects.DefectTrackerFactory;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.listFrom;
import static com.denimgroup.threadfix.CollectionUtils.setFrom;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/configuration/defecttrackers")
@SessionAttributes({"defectTracker","editDefectTracker"})
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
public class DefectTrackersController {
	
    @Autowired
	private DefectTrackerService defectTrackerService;

    @Autowired
    private DefectTrackerTypeService defectTrackerTypeService;

    @Autowired
    private ScheduledDefectTrackerUpdateService scheduledDefectTrackerUpdateService;

	private final SanitizedLogger log = new SanitizedLogger(DefectTrackersController.class);

	@RequestMapping(method = RequestMethod.GET)
	public String index(Model model) {
        model.addAttribute(new DefectTracker());
        PermissionUtils.addPermissions(model, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
        return "config/defecttrackers/index";
	}
	
	@RequestMapping("/{defectTrackerId}")
	public ModelAndView detail(@PathVariable("defectTrackerId") int defectTrackerId) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		
		if (defectTracker == null) {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
		
		ModelAndView mav = new ModelAndView("config/defecttrackers/detail");
		mav.addObject(defectTracker);
        PermissionUtils.addPermissions(mav, null, null, Permission.CAN_MANAGE_DEFECT_TRACKERS);
		return mav;
	}
	
	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("/{defectTrackerId}/delete")
	public @ResponseBody RestResponse<String> deleteTracker(@PathVariable("defectTrackerId") int defectTrackerId,
			SessionStatus status, Model model) {
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		if (defectTracker != null) {
			defectTrackerService.deleteById(defectTrackerId);
			return success("Defect Tracker was successfully deleted.");
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("DefectTracker", defectTrackerId));
			throw new ResourceNotFoundException();
		}
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("/info")
	public @ResponseBody RestResponse<Map<String, Object>> getList() {
		Map<String, Object> map = new HashMap<>();
        map.put("defectTrackerTypes", defectTrackerService.loadAllDefectTrackerTypes());
        map.put("defectTrackers", defectTrackerService.loadAllDefectTrackers());
        map.put("scheduledUpdates", scheduledDefectTrackerUpdateService.loadAll());
        return success(map);
	}

    // TODO move this elsewhere?
    @RequestMapping(value = "/jsontest", method = RequestMethod.POST)
    public @ResponseBody RestResponse<?> readJson(@Valid @ModelAttribute DefectTracker defectTracker, BindingResult result) {

        if(defectTracker.getUrl() == null){
            return failure("Missing defect tracker url.");
        }

        defectTracker.setDefectTrackerType(defectTrackerTypeService.loadById(defectTracker.getDefectTrackerType().getId()));

        if (!defectTrackerService.checkUrl(defectTracker, result)) {
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

        if (result.hasErrors()) {
            return FormRestResponse.failure("Found some errors.", result);
        }

        AbstractDefectTracker dt = DefectTrackerFactory.getTrackerByType(defectTracker, defectTracker.getDefaultUsername(), defectTracker.getDefaultPassword());

        if (dt == null) {
            log.warn("Incorrect Defect Tracker credentials submitted.");
            return failure("Authentication failed.");
        }
        List<String> productNames = dt.getProductNames();
        if (productNames.isEmpty() || (productNames.size() == 1 && productNames.contains("Authentication failed"))) {
            return failure(JSONObject.quote(dt.getLastError()));
        }

        // ensure there are no duplicates. There's probably a better idiom
        productNames = listFrom(setFrom(productNames));

        Collections.sort(productNames);

        return success(productNames);
    }
}
