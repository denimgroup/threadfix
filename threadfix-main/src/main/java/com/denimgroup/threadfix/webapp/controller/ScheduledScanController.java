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
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledScan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.ScheduledScanService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledScanScheduler;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Nullable;
import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scheduledScans")
@SessionAttributes(value= {"scanQueueTaskList", "scanQueueTask"})
public class ScheduledScanController {

	private final SanitizedLogger log = new SanitizedLogger(ScheduledScanController.class);

    @Nullable
    @Autowired(required = false)
    private ScheduledScanService scheduledScanService;

    @Autowired
    private ScheduledScanScheduler scheduledScanScheduler;

    @Autowired
    private ApplicationService applicationService;
	
	@RequestMapping(value = "/addScheduledScan", method = RequestMethod.POST)
	public @ResponseBody RestResponse<List<ScheduledScan>> addScheduledScan(@PathVariable("appId") int appId, @PathVariable("orgId") int orgId,
                                   @Valid @ModelAttribute ScheduledScan scheduledScan,
                                   BindingResult result) {

        if(scheduledScanService == null) {
            return RestResponse.failure("This method cannot be reached in the Community Edition.");
        }

		log.info("Start adding scheduled scan to application " + appId);

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)){
            return RestResponse.failure("You are not allowed to modify scheduled scans for this application.");
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null || !application.isActive()) {
            return RestResponse.failure("Application was not found for ID " + appId);
        }

        scheduledScanService.validateDate(scheduledScan, result);

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        scheduledScan.setApplication(application);

        String errMsg = scheduledScanService.validate(scheduledScan);
        if (errMsg != null) {
            return RestResponse.failure(errMsg);
        }

        int scheduledScanId = scheduledScanService.save(appId, scheduledScan);
		if (scheduledScanId < 0) {
			return RestResponse.failure("Adding Scheduled Scan failed.");
		}

        //Add new job to scheduler
        if (scheduledScanScheduler.addScheduledScan(scheduledScan)) {
            log.info("Successfully added new scheduled scan to scheduler");
            return RestResponse.success(application.getScheduledScans());

        } else {
            log.warn("Failed to add new scheduled scan to scheduler");
            String message = "Adding new "+ scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() + " failed.";

            scheduledScanService.delete(scheduledScan);
            return RestResponse.failure(message);
        }
	}

	@RequestMapping(value = "/scheduledScan/{scheduledScanId}/delete", method = RequestMethod.POST)
	public @ResponseBody RestResponse<String> delete(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@PathVariable("scheduledScanId") int scheduledScanId) {

        if(scheduledScanService == null) {
            return RestResponse.failure("This method cannot be reached in the Community Edition.");
        }
		
		log.info("Start deleting scheduled scan from application with id " + appId);

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS,orgId,appId)){
			return RestResponse.failure("You are not authorized to delete this scheduled scan.");
		}
        ScheduledScan scheduledScan = scheduledScanService.loadById(scheduledScanId);

        if (scheduledScan == null) {
            return RestResponse.failure("That scheduled scan was not found.");
        }

        //Remove job from scheduler
        if (scheduledScanScheduler.removeScheduledScan(scheduledScan)) {
            String ret = scheduledScanService.delete(scheduledScan);
            if (ret != null) {
                log.warn(ret);
                return RestResponse.failure(ret);
            } else {
                log.info("Successfully deleted scheduled scan from scheduler");
                return RestResponse.success(scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner()
                        + " Scheduled Scan successfully deleted.");
            }
        } else {
            String message = "Failed to delete " + scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() +
                    " scheduled scan from scheduler";
            log.warn(message);
            return RestResponse.failure(message);
        }
	}
}
