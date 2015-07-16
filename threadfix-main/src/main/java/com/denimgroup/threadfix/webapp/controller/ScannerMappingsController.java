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

import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.FindingService;
import com.denimgroup.threadfix.service.GenericVulnerabilityService;
import com.denimgroup.threadfix.service.ScannerMappingsExportService;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;



@Controller
@RequestMapping("/mappings")
@PreAuthorize("hasRole('ROLE_READ_ACCESS')")
public class ScannerMappingsController {

    @Autowired
	private ScannerMappingsUpdaterService scannerMappingsUpdaterService;
    @Autowired
    private ScannerMappingsExportService scannerMappingsExportService;
	@Autowired
	private GenericVulnerabilityService genericVulnerabilityService;
	@Autowired
	private FindingService findingService;

	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index(Model model) {
		
		model.addAttribute("pluginCheckBean", scannerMappingsUpdaterService.checkPluginJar());
        model.addAttribute("supportedScanners", scannerMappingsUpdaterService.getSupportedScanners());
		model.addAttribute("exportText", scannerMappingsExportService.getUserAddedMappingsInCSV());
        model.addAttribute("canUpdate", scannerMappingsExportService.canUpdate());

		return "mappings/channelVulnUpdate";
	}

	@RequestMapping(value = "/index/cwe", method = RequestMethod.GET)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object getCweList() {
		return RestResponse.success(genericVulnerabilityService.loadAll());
	}

	@RequestMapping(value = "/index/unmappedTable", method = RequestMethod.POST)
	@JsonView(AllViews.TableRow.class)
	@ResponseBody
	public Object unmappedScanTable(@ModelAttribute TableSortBean bean) throws IOException {

		if (!PermissionUtils.isAuthorized(Permission.READ_ACCESS, null, null)) {
			return "403";
		}

		// TODO remove repeated code from here + application page + scan page
		long numFindings = findingService.getTotalUnmappedFindings();
		long numPages = numFindings / 100;

		if (numFindings % 100 == 0) {
			numPages -= 1;
		}

		if (bean.getPage() >= numPages) {
			bean.setPage((int) (numPages + 1));
		}

		if (bean.getPage() < 1) {
			bean.setPage(1);
		}

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("numPages", numPages);
		responseMap.put("page", bean.getPage());
		responseMap.put("numFindings", numFindings);
		responseMap.put("findingList", findingService.getUnmappedFindingTable(bean));

		return RestResponse.success(responseMap);
	}
}

