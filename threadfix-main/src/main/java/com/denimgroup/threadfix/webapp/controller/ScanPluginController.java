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

import com.denimgroup.threadfix.importer.interop.ScannerMappingsUpdaterService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ScannerMappingsExportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Controller
@RequestMapping("/scanplugin")
public class ScanPluginController {

    @Autowired
	private ScannerMappingsUpdaterService scannerMappingsUpdaterService;
    @Autowired
    private ScannerMappingsExportService scannerMappingsExportService;

	private final SanitizedLogger log = new SanitizedLogger(ScanPluginController.class);

	@RequestMapping(value = "/index", method = RequestMethod.GET)
	public String index(Model model) {
		
		model.addAttribute("pluginCheckBean", scannerMappingsUpdaterService.checkPluginJar());
        model.addAttribute("supportedScanners", scannerMappingsUpdaterService.getSupportedScanners());
		model.addAttribute("exportText", scannerMappingsExportService.getUserAddedMappingsInCSV());
        model.addAttribute("canUpdate", scannerMappingsExportService.canUpdate());

		return "scanplugin/channelVulnUpdate";
	}

	@RequestMapping(value = "/updateChannelVuln", method = RequestMethod.GET)
	public String doUpdate(Model model) {
		log.info("Start updating Channel Vulnerabilities");
		List<String[]> channelVulnUpdateResults = list();
        List<String[]> genericVulnUpdateResults = list();
		
		try {
            genericVulnUpdateResults = scannerMappingsUpdaterService.updateGenericVulnerabilities();
            channelVulnUpdateResults = scannerMappingsUpdaterService.updateChannelVulnerabilities();
            scannerMappingsUpdaterService.updateUpdatedDate();

		} catch (URISyntaxException e) {
            String message = "There was error when reading files.";
			model.addAttribute("errorMessage", message);
            log.warn(message, e);
		} catch (IOException e) {
            String message = "There was error when updating Vulnerabilities.";
            model.addAttribute("errorMessage", message);
            log.warn(message, e);
		}
		
		model.addAttribute("successMessage", "Vulnerability mappings were successfully updated.");
		model.addAttribute("pluginCheckBean", scannerMappingsUpdaterService.checkPluginJar());
        model.addAttribute("resultList", channelVulnUpdateResults);
        model.addAttribute("genericVulnUpdateResults", genericVulnUpdateResults);
        model.addAttribute("supportedScanners", scannerMappingsUpdaterService.getSupportedScanners());

		log.info("Ended updating Vulnerabilities");
		return "scanplugin/channelVulnUpdate";
	}

}

