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

import java.util.List;

import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.service.LogParserService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.WafService;

@Controller
@RequestMapping("/wafs/{wafId}/upload")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_WAFS')")
public class UploadWafLogController {

	private LogParserService logParserService = null;
	private WafService wafService = null;
	
	private final SanitizedLogger log = new SanitizedLogger(WafsController.class);

	@Autowired
	public UploadWafLogController(WafService wafService, LogParserService logParserService) {
		this.logParserService = logParserService;
		this.wafService = wafService;
	}
	
	public UploadWafLogController(){}

	@RequestMapping(method = RequestMethod.GET)
	public String uploadIndex() {
		return "wafs/upload/form";
	}

	@RequestMapping(method = RequestMethod.POST)
	public String uploadSubmit(@PathVariable("wafId") int wafId, @RequestParam("file") MultipartFile file, 
			ModelMap model){
		
		if (wafService.loadWaf(wafId) == null) {
			log.warn(ResourceNotFoundException.getLogMessage("WAF", wafId));
			throw new ResourceNotFoundException();
		}
		
		if (file == null || file.getOriginalFilename() == null ||
				file.getOriginalFilename().equals("")) {
			return "redirect:/wafs/" + wafId;
		}
		
		// TODO put in a check to make sure the file is in the right format
		logParserService.setFile(file);
		logParserService.setWafId(wafId);
		List<SecurityEvent> events = logParserService.parseInput();
		model.addAttribute("eventList", events);
		return "wafs/upload/success";
	}
}
