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

import com.denimgroup.threadfix.data.entities.SecurityEvent;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.SecurityEventService;
import com.denimgroup.threadfix.webapp.utils.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/wafs/{wafId}/rule/{ruleId}/events")
public class SecurityEventController {

	@Autowired
	private SecurityEventService securityEventService;

	private final SanitizedLogger log = new SanitizedLogger(SecurityEventController.class);

	@RequestMapping("/{eventId}")
	public ModelAndView detail(@PathVariable("eventId") int eventId) {
		SecurityEvent securityEvent = securityEventService.loadSecurityEvent(eventId);
		if (securityEvent != null) {
			ModelAndView mav = new ModelAndView("wafs/events/detail");
			mav.addObject(securityEvent);
			return mav;
		} else {
			log.warn(ResourceNotFoundException.getLogMessage("SecurityEvent", eventId));
			throw new ResourceNotFoundException();
		}
	}
}
