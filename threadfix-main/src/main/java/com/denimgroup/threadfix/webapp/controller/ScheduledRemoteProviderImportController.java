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
 * Created by zabdisubhan on 8/14/14.
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

        scheduledRemoteProviderImportService.validateDate(scheduledRemoteProviderImport, result);

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        int scheduledRemoteProviderImportId = scheduledRemoteProviderImportService.save(scheduledRemoteProviderImport);
        if (scheduledRemoteProviderImportId < 0) {
            return RestResponse.failure("Adding Scheduled Remote Provider Import failed.");
        }

        //Add new job to scheduler
        if (scheduledRemoteProviderImporter.addScheduledRemoteProviderImport(scheduledRemoteProviderImport)) {
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
        if (scheduledRemoteProviderImporter.removeScheduledRemoteProviderImport(scheduledRemoteProviderImport)) {
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
