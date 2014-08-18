package com.denimgroup.threadfix.webapp.controller;

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledRemoteProviderUpdate;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ScheduledRemoteProviderUpdateService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledRemoteProviderUpdater;
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
import org.springframework.web.bind.annotation.SessionAttributes;

import javax.validation.Valid;
import java.util.List;

/**
 * Created by zabdisubhan on 8/14/14.
 */

@Controller
@RequestMapping("/configuration/remoteproviders/scheduledUpdates")
public class ScheduledRemoteProviderUpdateController {

    private final SanitizedLogger log = new SanitizedLogger(ScheduledRemoteProviderUpdateController.class);

    @Autowired
    private ScheduledRemoteProviderUpdateService scheduledRemoteProviderUpdateService;

    @Autowired
    private ScheduledRemoteProviderUpdater scheduledRemoteProviderUpdater;

    @RequestMapping(value = "/addUpdate", method = RequestMethod.POST)
    public @ResponseBody
    RestResponse<List<ScheduledRemoteProviderUpdate>> addScheduledRemoteProviderUpdate(@Valid @ModelAttribute ScheduledRemoteProviderUpdate scheduledRemoteProviderUpdate,
                                                       BindingResult result) {

        log.info("Start adding scheduled remote provider update.");

        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_REMOTE_PROVIDERS, null, null)){
            return RestResponse.failure("You are not allowed to modify scheduled remote provider updates.");
        }

        scheduledRemoteProviderUpdateService.validateDate(scheduledRemoteProviderUpdate, result);

        if (result.hasErrors()) {
            return FormRestResponse.failure("Encountered errors.", result);
        }

        int scheduledRemoteProviderUpdateId = scheduledRemoteProviderUpdateService.save(scheduledRemoteProviderUpdate);
        if (scheduledRemoteProviderUpdateId < 0) {
            return RestResponse.failure("Adding Scheduled Remote Provider Update failed.");
        }

        //Add new job to scheduler
        if (scheduledRemoteProviderUpdater.addScheduledRemoteProviderUpdate(scheduledRemoteProviderUpdate)) {
            log.info("Successfully added new scheduled remote provider update to scheduler");
            return RestResponse.success(scheduledRemoteProviderUpdateService.loadAll());

        } else {
            log.warn("Failed to add new scheduled remote provider update to scheduler");
            String message = "Adding new "+ scheduledRemoteProviderUpdate.getFrequency() + " Remote Provider Update failed.";

            scheduledRemoteProviderUpdateService.delete(scheduledRemoteProviderUpdate);
            return RestResponse.failure(message);
        }
    }

    @RequestMapping(value = "/update/{scheduledRemoteProviderUpdateId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> delete(@PathVariable("scheduledRemoteProviderUpdateId") int scheduledRemoteProviderUpdateId) {

        log.info("Start deleting scheduled remote provider update");
        if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_REMOTE_PROVIDERS, null, null)){
            return RestResponse.failure("You are not authorized to delete this scheduled remote provider update.");
        }
        ScheduledRemoteProviderUpdate scheduledRemoteProviderUpdate = scheduledRemoteProviderUpdateService.loadById(scheduledRemoteProviderUpdateId);
        if (scheduledRemoteProviderUpdate == null) {
            return RestResponse.failure("That scheduled remote provider update was not found.");
        }

        //Remove job from scheduler
        if (scheduledRemoteProviderUpdater.removeScheduledRemoteProviderUpdate(scheduledRemoteProviderUpdate)) {
            String ret = scheduledRemoteProviderUpdateService.delete(scheduledRemoteProviderUpdate);
            if (ret != null) {
                log.warn(ret);
                return RestResponse.failure(ret);
            } else {
                log.info("Successfully deleted scheduled remote provider update from scheduler");
                return RestResponse.success(scheduledRemoteProviderUpdate.getFrequency() + " Scheduled Remote Provider Update successfully deleted.");
            }
        } else {
            String message = "Failed to delete " + scheduledRemoteProviderUpdate.getFrequency() + " Remote Provider Update from scheduler";
            log.warn(message);
            return RestResponse.failure(message);
        }
    }
}
