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

import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefaultDefectProfileService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

@Controller
@RequestMapping("/default")
public class DefaultDefectProfileController {

	private final SanitizedLogger log = new SanitizedLogger(DefaultDefectProfileController.class);

	@Autowired
	private DefectTrackerService defectTrackerService;
	@Autowired
	private DefaultDefectProfileService defaultDefectProfileService;

	@JsonView(Object.class)
	@RequestMapping(value = "profiles/{defectTrackerId}", method = RequestMethod.GET)
	public @ResponseBody RestResponse<Map<String, Object>> getDefaultProfiles(
			@PathVariable("defectTrackerId") int defectTrackerId) {
		Map<String, Object> map = map();
		DefectTracker defectTracker = defectTrackerService.loadDefectTracker(defectTrackerId);
		map.put("defaultProfiles", defectTracker.getDefaultDefectProfiles());
		return RestResponse.success(map);
	}

	@PreAuthorize("hasRole('ROLE_CAN_MANAGE_DEFECT_TRACKERS')")
	@RequestMapping("profiles/delete/{defaultProfileId}")
	public @ResponseBody RestResponse<String> deleteDefaultDefectProfile(
			@PathVariable("defaultProfileId") int defaultProfileId,	SessionStatus status, Model model) {
		log.info("Deleting a profile based on id");
		DefaultDefectProfile defaultProfile = defaultDefectProfileService.loadDefaultProfile(defaultProfileId);
		if (defaultProfile != null) {
			defaultDefectProfileService.deleteProfileById(defaultProfileId);
			return RestResponse.success("Default defect profile was successfully deleted.");
		} else {
			return RestResponse.failure("Could not delete, bad request");
		}
	}
}
