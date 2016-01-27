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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledDefectTrackerUpdate;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ScheduledDefectTrackerUpdateService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledDefectTrackerUpdater;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ModelAttribute;

import javax.validation.Valid;
import java.util.List;

/**
 * @author zabdisubhan
 *
 */

@Controller
@RequestMapping("/configuration/defecttrackers/scheduledUpdates")
public class ScheduledDefectTrackerUpdateController {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledDefectTrackerUpdateController.class);

    @Autowired
    private ScheduledDefectTrackerUpdateService scheduledDefectTrackerUpdateService;

    @Autowired
    private ScheduledDefectTrackerUpdater scheduledDefectTrackerUpdater;

    @RequestMapping(value = "/addUpdate", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<List<ScheduledDefectTrackerUpdate>> addScheduledDefectTrackerUpdate(
            @Valid @ModelAttribute ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate,
            BindingResult result) {

        log.info("Start adding scheduled defect tracker update.");

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS, null, null)){
            return RestResponse.failure("You are not allowed to modify scheduled defect tracker updates.");
        }

        if (scheduledDefectTrackerUpdate.getScheduleType().equals("CRON")) {
            scheduledDefectTrackerUpdate.clearDate();
            scheduledDefectTrackerUpdateService.validateCronExpression(scheduledDefectTrackerUpdate, result);
        } else if (scheduledDefectTrackerUpdate.getScheduleType().equals("SELECT")) {
            scheduledDefectTrackerUpdate.clearCronExpression();
            scheduledDefectTrackerUpdateService.validateDate(scheduledDefectTrackerUpdate, result);
            scheduledDefectTrackerUpdateService.validateSameDate(scheduledDefectTrackerUpdate, result);
        }

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        if (scheduledDefectTrackerUpdateService.save(scheduledDefectTrackerUpdate) < 0) {
            return RestResponse.failure("Adding Scheduled Defect Tracker Update failed.");
        }

        //Add new job to scheduler
        if (scheduledDefectTrackerUpdater.addScheduledJob(scheduledDefectTrackerUpdate)) {
            log.info("Successfully added new scheduled defect tracker update to scheduler");
            return RestResponse.success(scheduledDefectTrackerUpdateService.loadAll());

        } else {
            log.warn("Failed to add new scheduled defect tracker update to scheduler");
            String message = "Adding new "+ scheduledDefectTrackerUpdate.getFrequency() +
                    " Defect Tracker Update failed.";

            scheduledDefectTrackerUpdateService.delete(scheduledDefectTrackerUpdate);
            return RestResponse.failure(message);
        }
    }

    @RequestMapping(value = "/update/{scheduledDefectTrackerUpdateId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(
            @PathVariable("scheduledDefectTrackerUpdateId") int scheduledDefectTrackerUpdateId) {

        log.info("Start deleting scheduled defect tracker update");
        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS, null, null)){
            return RestResponse.failure("You are not authorized to delete this scheduled defect tracker update.");
        }
        ScheduledDefectTrackerUpdate scheduledDefectTrackerUpdate = scheduledDefectTrackerUpdateService.loadById(scheduledDefectTrackerUpdateId);
        if (scheduledDefectTrackerUpdate == null) {
            return RestResponse.failure("That scheduled defect tracker update was not found.");
        }

        //Remove job from scheduler
        if (scheduledDefectTrackerUpdater.removeScheduledJob(scheduledDefectTrackerUpdate)) {
            String ret = scheduledDefectTrackerUpdateService.delete(scheduledDefectTrackerUpdate);
            if (ret != null) {
                log.warn(ret);
                return RestResponse.failure(ret);
            } else {
                log.info("Successfully deleted scheduled defect tracker update from scheduler");
                return RestResponse.success(scheduledDefectTrackerUpdate.getFrequency() + " Scheduled Defect Tracker Update successfully deleted.");
            }
        } else {
            String message = "Failed to delete " + scheduledDefectTrackerUpdate.getFrequency() + " Defect Tracker Update from scheduler";
            log.warn(message);
            return RestResponse.failure(message);
        }
    }
}
