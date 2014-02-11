////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.data.entities.ScheduledScan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.service.ScheduledScanService;
import com.denimgroup.threadfix.service.queue.scheduledjob.ScheduledScanScheduler;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Controller
@RequestMapping("/organizations/{orgId}/applications/{appId}/scheduledScans")
@SessionAttributes(value= {"scanQueueTaskList", "scanQueueTask"})
public class ScheduledScanController {

	private final SanitizedLogger log = new SanitizedLogger(ScheduledScanController.class);

    @Autowired
	private ScheduledScanService scheduledScanService;
    @Autowired
    private ChannelTypeService channelTypeService;

    @Autowired
    private ScheduledScanScheduler scheduledScanScheduler;
	
	@RequestMapping(value = "/addScheduledScan", method = RequestMethod.POST)
	public String addScheduledScan(@PathVariable("appId") int appId, @PathVariable("orgId") int orgId,
                                   @Valid @ModelAttribute ScheduledScan scheduledScan,
                                   BindingResult result,
                                   HttpServletRequest request, Model model) {
		log.info("Start adding scheduled scan to application " + appId);
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, orgId, appId)){
            return "403";
        }
        scheduledScanService.validateScheduledDate(scheduledScan, result);
        if (result.hasErrors()) {
            List<String> scannerTypeList = new ArrayList<>();
            List<ChannelType> channelTypeList = channelTypeService.getChannelTypeOptions(null);
            for (ChannelType type: channelTypeList) {
                scannerTypeList.add(type.getName());
            }
            Collections.sort(scannerTypeList);
            model.addAttribute("scannerTypeList", scannerTypeList);
            model.addAttribute("frequencyTypes", ScheduledScan.ScheduledFrequencyType.values());
            model.addAttribute("periodTypes", ScheduledScan.ScheduledPeriodType.values());
            model.addAttribute("scheduledDays", ScheduledScan.DayInWeek.values());
            model.addAttribute("contentPage", "applications/forms/addScheduledScanForm.jsp");
            return "ajaxFailureHarness";
        }

        int scheduledScanId = scheduledScanService.saveScheduledScan(appId, scheduledScan);
		if (scheduledScanId < 0) {
			ControllerUtils.addErrorMessage(request,
                    "Adding Scheduled Scan was failed.");
            ControllerUtils.setActiveTab(request, ControllerUtils.SCHEDULED_SCAN_TAB);
			model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
			return "ajaxFailureHarness";
		}

        //Add new job to scheduler
        String successMsg = "";
        if (scheduledScanScheduler.addScheduledScan(scheduledScan)) {
            successMsg = "New " + scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() +
                    " was added to the Scan Scheduler " +
                    (scheduledScan.getDay()!=null && !scheduledScan.getDay().isEmpty() ? "every " + scheduledScan.getDay() + " " : "") +
                    "at " + getTimeByString(scheduledScan);

            log.info("Successfully added new scheduled scan to scheduler");
            ControllerUtils.addSuccessMessage(request, successMsg);
            ControllerUtils.setActiveTab(request, ControllerUtils.SCHEDULED_SCAN_TAB);
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
            log.info("Ended adding scheduled scan to application " + appId);
            return "ajaxRedirectHarness";

        } else {
            log.warn("Failed to add new scheduled scan to scheduler");
            ControllerUtils.addErrorMessage(request,
                    "Adding new "+ scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() + " was failed.");

            scheduledScanService.deleteScheduledScan(scheduledScan);
            ControllerUtils.setActiveTab(request, ControllerUtils.SCHEDULED_SCAN_TAB);
            model.addAttribute("contentPage", "/organizations/" + orgId + "/applications/" + appId);
            return "ajaxFailureHarness";
        }
	}

    private String getTimeByString(ScheduledScan scheduledScan) {
        String minStr = (scheduledScan.getMinute()<10) ?
                "0" + String.valueOf(scheduledScan.getMinute()) : String.valueOf(scheduledScan.getMinute());
        return String.valueOf(scheduledScan.getHour()) + ":" + minStr + " " + scheduledScan.getPeriod();
    }

	@RequestMapping(value = "/scheduledScan/{scheduledScanId}/delete", method = RequestMethod.POST)
	public String deleteScheduledScan(@PathVariable("appId") int appId,
			@PathVariable("orgId") int orgId,
			@PathVariable("scheduledScanId") int scheduledScanId,
			HttpServletRequest request, Model model) {
		
		log.info("Start deleting scheduled scan from application with id " + appId);
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS,orgId,appId)){
			return "403";
		}
        ScheduledScan scheduledScan = scheduledScanService.loadScheduledScanById(scheduledScanId);
        if (scheduledScan == null) {
            ControllerUtils.addErrorMessage(request, "The scan submitted was invalid, unable to delete");
            ControllerUtils.setActiveTab(request, ControllerUtils.SCHEDULED_SCAN_TAB);
            return "redirect:/organizations/" + orgId + "/applications/" + appId;
        }

        //Remove job from scheduler
        if (scheduledScanScheduler.removeScheduledScan(scheduledScan)) {
            String ret = scheduledScanService.deleteScheduledScan(scheduledScan);
            if (ret != null) {
                ControllerUtils.addErrorMessage(request, ret);
            } else {
                String successMsg = scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() +
                        " was deleted from Scan Scheduler ";
                ControllerUtils.addSuccessMessage(request, successMsg);
            }
            log.info("Successfully deleted scheduled scan from scheduler");
        } else {
            String errorMsg = scheduledScan.getFrequency() + " Scan for " + scheduledScan.getScanner() +
                    " was failed to delete from Scan Scheduler ";
            ControllerUtils.addErrorMessage(request, errorMsg);
            log.warn("Failed to delete scheduled scan from scheduler");
        }
        ControllerUtils.setActiveTab(request, ControllerUtils.SCHEDULED_SCAN_TAB);
        log.info("Ended deleting scheduled scan from application with Id " + appId);

        return "redirect:/organizations/" + orgId + "/applications/" + appId;
	}

}
