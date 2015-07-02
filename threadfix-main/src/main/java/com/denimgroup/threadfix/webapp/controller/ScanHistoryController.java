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

import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GenericSeverityService;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/scans")
public class ScanHistoryController {

	private final SanitizedLogger log = new SanitizedLogger(ScanHistoryController.class);

	@Autowired
	private ScanService scanService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView viewScans() {
		log.debug("Hit scan history page.");

		return new ModelAndView("scans/history");
	}

	@JsonView(AllViews.TableRow.class)
	@RequestMapping(value="/table/{pageNumber}", method = RequestMethod.POST)
	@ResponseBody
	public Object getScanTable(@PathVariable int pageNumber) throws IOException {

		int scanCount = scanService.getScanCount();
		int totalPages = (scanCount / 100) + 1;
		if (scanCount % 100 == 0) {
			totalPages -= 1;
		}
		if (pageNumber > totalPages) {
            pageNumber = totalPages;
        }
		if (pageNumber < 1) {
            pageNumber = 1;
        }
		
		List<Scan> scans = scanService.getTableScans(pageNumber);

        Map<String, Object> map = new HashMap<>();
		map.put("scanList", scans);
		map.put("numScans", scanCount);
		map.put("genericSeverities", genericSeverityService.loadAll());
        return RestResponse.success(map);
	}
	

}