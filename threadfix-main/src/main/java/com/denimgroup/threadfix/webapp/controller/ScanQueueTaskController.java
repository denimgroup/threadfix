////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.denimgroup.threadfix.data.entities.APIKey;
import com.denimgroup.threadfix.service.APIKeyService;
import com.denimgroup.threadfix.service.ScanQueueService;

@Controller
@RequestMapping("/configuration/scanqueue")
public class ScanQueueTaskController {

	private ScanQueueService scanQueueService;
	
	@Autowired
	public ScanQueueTaskController(ScanQueueService scanQueueService) {
		this.scanQueueService = scanQueueService;
	}
	
	@RequestMapping(method = RequestMethod.GET)
	public String index(HttpServletRequest request, Model model) {
		model.addAttribute("scanQueueTaskList", scanQueueService.loadAll());
		
		
		return "config/scanqueue/index";
	}
	
	@RequestMapping(value = "/{scanQueueTaskId}/detail", method = RequestMethod.GET)
	public String showDetail(@PathVariable("scanQueueTaskId") int scanQueueTaskId, Model model,
			HttpServletRequest request) {
		
		model.addAttribute("scanQueueTask", scanQueueService.retrieveById(scanQueueTaskId));
		
		return("config/scanqueue/detail");
	}
}
