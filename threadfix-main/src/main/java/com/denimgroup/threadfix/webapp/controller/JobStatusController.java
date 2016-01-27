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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.service.JobStatusService;

@Controller
@RequestMapping("/jobs")
//@PreAuthorize("hasRole('ROLE_CAN_VIEW_JOB_STATUSES')")
public class JobStatusController {
	
	public JobStatusController(){}

	private JobStatusService jobStatusService = null;

	@Autowired
	public JobStatusController(JobStatusService jobStatusService) {
		this.jobStatusService = jobStatusService;
	}

	@RequestMapping(value = "/open", method = RequestMethod.GET)
	public String showOpenJobs(ModelMap model) {
		model.addAttribute(jobStatusService.loadAllOpen());
		model.addAttribute("viewAll", false);
		return "config/jobs";
	}

	@RequestMapping(value = "/all", method = RequestMethod.GET)
	public String showAllJobs(ModelMap model) {
		model.addAttribute(jobStatusService.loadAll());
		model.addAttribute("viewAll", true);
		return "config/jobs";
	}

}
