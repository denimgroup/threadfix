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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledGRCToolUpdate;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ScheduledGRCToolUpdateService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledGRCToolUpdater;
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
@RequestMapping("/configuration/grctools/scheduledUpdates")
public class ScheduledGRCToolUpdateController {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledGRCToolUpdateController.class);

    @Autowired(required = false)
    private ScheduledGRCToolUpdateService scheduledGRCToolUpdateService;

    @Autowired
    private ScheduledGRCToolUpdater scheduledGRCToolUpdater;

    @RequestMapping(value = "/addUpdate", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<List<ScheduledGRCToolUpdate>> addScheduledGRCToolUpdate(
            @Valid @ModelAttribute ScheduledGRCToolUpdate scheduledGRCToolUpdate,
            BindingResult result) {

        if (scheduledGRCToolUpdateService == null) {
            return RestResponse.failure("This method cannot be reached in the Community Edition.");
        }

        log.info("Start adding scheduled GRC tool update.");

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS, null, null)){
            return RestResponse.failure("You are not allowed to modify scheduled GRC tool updates.");
        }

        if (scheduledGRCToolUpdate.getScheduleType().equals("CRON")) {
            scheduledGRCToolUpdate.clearDate();
            scheduledGRCToolUpdateService.validateCronExpression(scheduledGRCToolUpdate, result);
        } else if (scheduledGRCToolUpdate.getScheduleType().equals("SELECT")) {
            scheduledGRCToolUpdate.clearCronExpression();
            scheduledGRCToolUpdateService.validateDate(scheduledGRCToolUpdate, result);
            scheduledGRCToolUpdateService.validateSameDate(scheduledGRCToolUpdate, result);
        }

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        if (scheduledGRCToolUpdateService.save(scheduledGRCToolUpdate) < 0) {
            return RestResponse.failure("Adding Scheduled GRC Tool Update failed.");
        }

        //Add new job to scheduler
        if (scheduledGRCToolUpdater.addScheduledJob(scheduledGRCToolUpdate)) {
            log.info("Successfully added new scheduled GRC tool update to scheduler");
            return RestResponse.success(scheduledGRCToolUpdateService.loadAll());

        } else {
            log.warn("Failed to add new scheduled GRC tool update to scheduler");
            String message = "Adding new "+ scheduledGRCToolUpdate.getFrequency() +
                    " GRC Tool Update failed.";

            scheduledGRCToolUpdateService.delete(scheduledGRCToolUpdate);
            return RestResponse.failure(message);
        }
    }

    @RequestMapping(value = "/update/{scheduledGRCToolUpdateId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(
            @PathVariable("scheduledGRCToolUpdateId") int scheduledGRCToolUpdateId) {

        if (scheduledGRCToolUpdateService == null) {
            return RestResponse.failure("This method cannot be reached in the Community Edition.");
        }

        log.info("Start deleting scheduled GRC tool update");

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_DEFECT_TRACKERS, null, null)){
            return RestResponse.failure("You are not authorized to delete this scheduled GRC tool update.");
        }

        ScheduledGRCToolUpdate scheduledGRCToolUpdate = scheduledGRCToolUpdateService.loadById(scheduledGRCToolUpdateId);
        if (scheduledGRCToolUpdate == null) {
            return RestResponse.failure("That scheduled GRC tool update was not found.");
        }

        //Remove job from scheduler
        if (scheduledGRCToolUpdater.removeScheduledJob(scheduledGRCToolUpdate)) {
            String ret = scheduledGRCToolUpdateService.delete(scheduledGRCToolUpdate);
            if (ret != null) {
                log.warn(ret);
                return RestResponse.failure(ret);
            } else {
                log.info("Successfully deleted scheduled GRC tool update from scheduler");
                return RestResponse.success(scheduledGRCToolUpdate.getFrequency() + " Scheduled GRC Tool Update successfully deleted.");
            }
        } else {
            String message = "Failed to delete " + scheduledGRCToolUpdate.getFrequency() + " GRC Tool Update from scheduler";
            log.warn(message);
            return RestResponse.failure(message);
        }
    }
}
