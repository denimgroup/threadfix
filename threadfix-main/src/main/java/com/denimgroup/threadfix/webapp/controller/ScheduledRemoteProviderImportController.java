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
import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderImport;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ScheduledRemoteProviderImportService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledRemoteProviderImporter;
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
@RequestMapping("/configuration/remoteproviders/scheduledImports")
public class ScheduledRemoteProviderImportController {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderImportController.class);

    @Autowired
    private ScheduledRemoteProviderImportService scheduledRemoteProviderImportService;

    @Autowired
    private ScheduledRemoteProviderImporter scheduledRemoteProviderImporter;

    @RequestMapping(value = "/addImport", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<List<ScheduledRemoteProviderImport>> addScheduledRemoteProviderImport(
            @Valid @ModelAttribute ScheduledRemoteProviderImport scheduledRemoteProviderImport,
                                                       BindingResult result) {

        log.info("Start adding scheduled remote provider import.");

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_REMOTE_PROVIDERS, null, null)){
            return RestResponse.failure("You are not allowed to modify scheduled remote provider imports.");
        }

        if (scheduledRemoteProviderImport.getScheduleType().equals("CRON")) {
            scheduledRemoteProviderImport.clearDate();
            scheduledRemoteProviderImportService.validateCronExpression(scheduledRemoteProviderImport, result);
        } else if (scheduledRemoteProviderImport.getScheduleType().equals("SELECT")) {
            scheduledRemoteProviderImport.clearCronExpression();
            scheduledRemoteProviderImportService.validateDate(scheduledRemoteProviderImport, result);
            scheduledRemoteProviderImportService.validateSameDate(scheduledRemoteProviderImport, result);
        }

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        if (scheduledRemoteProviderImportService.save(scheduledRemoteProviderImport) < 0) {
            return RestResponse.failure("Adding Scheduled Remote Provider Import failed.");
        }

        //Add new job to scheduler
        if (scheduledRemoteProviderImporter.addScheduledJob(scheduledRemoteProviderImport)) {
            log.info("Successfully added new scheduled remote provider import to scheduler");
            return RestResponse.success(scheduledRemoteProviderImportService.loadAll());

        } else {
            log.warn("Failed to add new scheduled remote provider import to scheduler");
            String message = "Adding new "+ scheduledRemoteProviderImport.getFrequency() +
                    " Remote Provider Import failed.";

            scheduledRemoteProviderImportService.delete(scheduledRemoteProviderImport);
            return RestResponse.failure(message);
        }
    }

    @RequestMapping(value = "/import/{scheduledRemoteProviderImportId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(
            @PathVariable("scheduledRemoteProviderImportId") int scheduledRemoteProviderImportId) {

        log.info("Start deleting scheduled remote provider import");
        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_REMOTE_PROVIDERS, null, null)){
            return RestResponse.failure("You are not authorized to delete this scheduled remote provider import.");
        }
        ScheduledRemoteProviderImport scheduledRemoteProviderImport = scheduledRemoteProviderImportService.loadById(scheduledRemoteProviderImportId);
        if (scheduledRemoteProviderImport == null) {
            return RestResponse.failure("That scheduled remote provider import was not found.");
        }

        //Remove job from scheduler
        if (scheduledRemoteProviderImporter.removeScheduledJob(scheduledRemoteProviderImport)) {
            String ret = scheduledRemoteProviderImportService.delete(scheduledRemoteProviderImport);
            if (ret != null) {
                log.warn(ret);
                return RestResponse.failure(ret);
            } else {
                log.info("Successfully deleted scheduled remote provider import from scheduler");
                return RestResponse.success(scheduledRemoteProviderImport.getFrequency() + " Scheduled Remote Provider Import successfully deleted.");
            }
        } else {
            String message = "Failed to delete " + scheduledRemoteProviderImport.getFrequency() + " Remote Provider Import from scheduler";
            log.warn(message);
            return RestResponse.failure(message);
        }
    }
}
