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

import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ExceptionLogService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/configuration/logs")
@PreAuthorize("hasRole('ROLE_CAN_VIEW_ERROR_LOGS')")
public class ErrorLogController {
	
	public ErrorLogController(){}
	
	@Autowired
	ExceptionLogService exceptionLogService;
	
	@RequestMapping(method = RequestMethod.GET)
	public String manageUsers() {
		return "config/logs";
	}

    @RequestMapping(value="/page/{page}/{numberToShow}", method = RequestMethod.GET)
	@ResponseBody
	public RestResponse<Map<String, Object>> getPage(
			@PathVariable int page,
			@PathVariable int numberToShow,
			HttpServletRequest request) {

        Map<String, Object> map = new HashMap<>();
        map.put("logs", exceptionLogService.loadPage(page, numberToShow));
        map.put("totalLogs", exceptionLogService.countLogs());
		Object logId = ControllerUtils.getItem(request, "logId");
		if (logId != null) {
			map.put("logIdToExpand", logId);
		}

        return RestResponse.success(map);
    }
	
	@RequestMapping(value="/{logId}", method = RequestMethod.GET)
	public String manageUsers(
			HttpServletRequest request,
			@PathVariable("logId") int logId) {
		ControllerUtils.addItem(request, "logId", logId);
		return "redirect:/configuration/logs";
	}
}
