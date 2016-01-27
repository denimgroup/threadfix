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

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Permission;
import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
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
	@Autowired
	private ChannelTypeService channelTypeService;
	@Autowired
	private ChannelVulnerabilityService channelVulnerabilityService;
	@Autowired(required = false)
	private ChannelVulnerabilityFilterService channelVulnerabilityFilterService;
	@Autowired
	private GenericSeverityService genericSeverityService;

	@InitBinder
	protected void initBinder(WebDataBinder binder) {
		binder.setValidator(new BeanValidator());
	}

	@RequestMapping(value = "/filters/map", method = RequestMethod.GET)
	@ResponseBody
	public RestResponse<Map<String, Object>> mapBackend() {
		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, null, null)) {
			return RestResponse.failure("You don't have permission to access these filters.");
		}

		Map<String, Object> map = CollectionUtils.map();

		map.put("genericSeverities", genericSeverityService.loadAll());

		if (EnterpriseTest.isEnterprise()) {
			if (channelVulnerabilityFilterService == null) {
				throw new IllegalStateException();
			}

			List<ChannelType> channelTypes = channelTypeService.loadAllHasVulnMapping();
			map.put("channelVulnerabilitiesMap", channelVulnerabilityService.getChannelVulnsEachChannelType(channelTypes));
			map.put("channelTypes", channelTypes);
			map.put("type", "Global");
			map.put("globalChannelVulnFilterList", channelVulnerabilityFilterService.retrieveAll());
		}

		return RestResponse.success(map);
	}

	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index(Model model) {

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, null, null)) {
			return "403";
		}

		model.addAttribute("pluginCheckBean", scannerMappingsUpdaterService.checkPluginJar());
        model.addAttribute("supportedScanners", scannerMappingsUpdaterService.getSupportedScanners());
		model.addAttribute("exportText", scannerMappingsExportService.getUserAddedMappingsInCSV());
        model.addAttribute("canUpdate", scannerMappingsExportService.canUpdate());
        model.addAttribute("exportUnmappedText", findingService.getUnmappedTypesAsString() );

		if (EnterpriseTest.isEnterprise()) {
			return "customize/scannerVulnTypes/enterprise";
		} else {
			return "customize/scannerVulnTypes/community";
		}

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

		if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_VULN_FILTERS, null, null)) {
			return "403";
		}

		long numFindings = findingService.getTotalUnmappedFindings();

		if (bean.getPage() < 1) {
			bean.setPage(1);
		}

		Map<String, Object> responseMap = new HashMap<>();
		responseMap.put("page", bean.getPage());
		responseMap.put("numFindings", numFindings);
		responseMap.put("findingList", findingService.getUnmappedFindingTable(bean));

		return RestResponse.success(responseMap);
	}
}

