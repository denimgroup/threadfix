package com.denimgroup.threadfix.webapp.controller;

import static com.denimgroup.threadfix.CollectionUtils.map;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import com.denimgroup.threadfix.data.dao.DefaultDefectProfileDao;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.DefectTracker;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.DefaultDefectProfileService;
import com.denimgroup.threadfix.service.DefectTrackerService;
import com.fasterxml.jackson.annotation.JsonView;

@Controller
@RequestMapping("/default")
public class DefaultDefectProfileController {

	private final SanitizedLogger log = new SanitizedLogger(DefaultDefectProfileController.class);

	@Autowired
	private DefectTrackerService defectTrackerService;
	@Autowired
	private DefaultDefectProfileService defaultDefectProfileService;
	@Autowired
	private DefaultDefectProfileDao defaultDefectProfiledao;

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
