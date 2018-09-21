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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.DefectService;
import com.denimgroup.threadfix.service.VulnerabilityService;
import com.denimgroup.threadfix.service.queue.QueueSender;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import com.denimgroup.threadfix.viewmodels.DefectViewModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/defects")
@SessionAttributes("defectViewModel")
public class DefectsController {
	
	public DefectsController(){}
	
	private final SanitizedLogger log = new SanitizedLogger(DefectsController.class);

	private ApplicationService applicationService;
	private QueueSender queueSender;
	private VulnerabilityService vulnerabilityService;
	private DefectService defectService;

	@Autowired
	public DefectsController(ApplicationService applicationService, 
			QueueSender queueSender,
			VulnerabilityService vulnerabilityService,
			DefectService defectService) {
		this.queueSender = queueSender;
		this.applicationService = applicationService;
		this.vulnerabilityService = vulnerabilityService;
		this.defectService = defectService;
	}

	@RequestMapping(method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> onSubmit(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			@ModelAttribute DefectViewModel defectViewModel) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_SUBMIT_DEFECTS, orgId, appId)) {
			return RestResponse.failure("You don't have permission to submit defects.");
		}
		
		if (defectViewModel.getVulnerabilityIds() == null
				|| defectViewModel.getVulnerabilityIds().size() == 0) {
			return RestResponse.failure("You must select at least one vulnerability.");
		}

        Map<String,Object> fieldsMap = defectViewModel.getFieldsMap();
        Object asi = fieldsMap.get("AdditionalScannerInfo");

        if (asi != null) {
            if ((Boolean) asi){
                defectViewModel.setAdditionalScannerInfo(true);
            }
        } else {
            if(defectViewModel.getAdditionalScannerInfo() == null){
                defectViewModel.setAdditionalScannerInfo(false);
            }
        }

		List<Vulnerability> vulnerabilities = vulnerabilityService.loadVulnerabilityList(defectViewModel.getVulnerabilityIds());
		Map<String,Object> map = defectService.createDefect(vulnerabilities, defectViewModel.getSummary(),
				defectViewModel.getPreamble(), 
				defectViewModel.getSelectedComponent(), 
				defectViewModel.getVersion(), 
				defectViewModel.getSeverity(), 
				defectViewModel.getPriority(), 
				defectViewModel.getStatus(),
                defectViewModel.getFieldsMap(),
                defectViewModel.getAdditionalScannerInfo());
        Defect newDefect = null;
        if (map.get(DefectService.DEFECT) instanceof Defect)
            newDefect = (Defect)map.get(DefectService.DEFECT);
		if (newDefect != null) {
			return RestResponse.success("The Defect was submitted to the tracker.");
        } else {
            return RestResponse.failure(map.get(DefectService.ERROR) == null ?
                    "The Defect couldn't be submitted to the tracker." : map.get(DefectService.ERROR).toString());
        }
	}

	@RequestMapping(value = "/update", method = RequestMethod.GET)
	public @ResponseBody RestResponse<String> updateVulnsFromDefectTracker(@PathVariable("orgId") int orgId,
			@PathVariable("appId") int appId) {
		
		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, orgId, appId)) {
			return RestResponse.failure("You don't have permission to pull updates from the tracker.");
        }
		
		Application app = applicationService.loadApplication(appId);
		
		if (app == null || app.getOrganization() == null || app.getOrganization().getId() == null) {
			log.warn(ResourceNotFoundException.getLogMessage("Application", appId));
			throw new ResourceNotFoundException();
		}
		
		queueSender.addDefectTrackerVulnUpdate(orgId, appId);

		return RestResponse.success("The Defect Tracker update request was submitted to the tracker.");
	}

	@RequestMapping(value = "/merge", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> onMerge(@PathVariable("orgId") int orgId, @PathVariable("appId") int appId,
			@ModelAttribute DefectViewModel defectViewModel) {
		
		if (!PermissionUtils.isAuthorized(Permission.CAN_SUBMIT_DEFECTS, orgId, appId)) {
			return RestResponse.failure("You don't have permission to modify defects.");
		}
		
		List<Integer> vulnerabilityIds = defectViewModel.getVulnerabilityIds();
		if (vulnerabilityIds == null || vulnerabilityIds.size() == 0) {
			return RestResponse.failure("You must select at least one vulnerability.");
        }

		List<Vulnerability> vulnerabilities = vulnerabilityService.loadVulnerabilityList(vulnerabilityIds);

        int size = defectViewModel.getVulnerabilityIds().size();
        String pluralized = size == 1 ? "1 vulnerability" : size + " vulnerabilities";

		if (defectService.mergeDefect(vulnerabilities, defectViewModel.getId())) {
            return RestResponse.success("Successfully merged " + pluralized + " to Defect ID " + defectViewModel.getId());
		} else {
            return RestResponse.failure("Failed to merge " + pluralized + " to Defect ID " + defectViewModel.getId() + ". " +
					"Double check the Defect ID.");
		}
	}
}
