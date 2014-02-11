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
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ScanService;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import java.util.List;

@Controller
@RequestMapping("/scans")
public class ScanHistoryController {

	private final SanitizedLogger log = new SanitizedLogger(ScanHistoryController.class);

	private ScanService scanService;

	@Autowired
	public ScanHistoryController(ScanService scanService) {
		this.scanService = scanService;
	}

	public ScanHistoryController(){}

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}

	@RequestMapping(method = RequestMethod.GET)
	public ModelAndView viewScans() {
		log.info("Hit scan history page.");

		ModelAndView mav = new ModelAndView("scans/history");
		return mav;
	}
	
	@RequestMapping(value="/table",method = RequestMethod.POST)
	public ModelAndView getScanTable(@RequestBody TableSortBean bean) {

		int page = 0, scanCount = 0, totalPages = 0;
		
		page = bean.getPage();
		scanCount = scanService.getScanCount();
		totalPages = (scanCount / 100) + 1;
		if (scanCount % 100 == 0) {
			totalPages -= 1;
		}
		if (page > totalPages) page = totalPages;
		if (page < 1) page = 1;
		
		List<Scan> scans = scanService.getTableScans(page);
		
		ModelAndView mav = new ModelAndView("scans/historyTable");
		mav.addObject("scanList", scans);
		mav.addObject("scanTypes", getTypes(scans));
		mav.addObject("numPages", totalPages);
		mav.addObject("page", page);
		mav.addObject("numScans", scanCount);
		return mav;
	}
	
	private String[] getTypes(List<Scan> scanList) {
		String[] types = new String[scanList.size()];
		for (int i = 0; i < scanList.size(); i++) {
			Scan scan = scanList.get(i);
			String type = scan.getApplicationChannel().getChannelType().getName();
			if (ChannelType.DYNAMIC_TYPES.contains(type)) {
				types[i] = ChannelType.DYNAMIC;
			} else if (ChannelType.STATIC_TYPES.contains(type)) {
				types[i] = ChannelType.STATIC;
			} else if (ChannelType.MIXED_TYPES.contains(type)) {
				types[i] = ChannelType.MIXED;
			}
		}
		return types;
	}
}