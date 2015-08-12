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
import com.denimgroup.threadfix.service.ChannelVulnerabilityService;
import com.denimgroup.threadfix.service.VulnerabilityFilterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@Controller
@RequestMapping("/scannerMappings/update")
public class ScannerMappingUpdateController {

    @Autowired
    public ChannelVulnerabilityService channelVulnerabilityService;

    @Autowired
    public VulnerabilityFilterService vulnerabilityFilterService;

    @RequestMapping(method = RequestMethod.POST)
    @ResponseBody
    public RestResponse<String> addMappings(@RequestParam String channelName,
                                              @RequestParam int channelVulnerabilityId,
                                              @RequestParam String genericVulnerabilityId) {

        ChannelVulnerabilityService.MappingCreateResult result =
                channelVulnerabilityService.createMapping(channelName, channelVulnerabilityId, genericVulnerabilityId);

        if (result == ChannelVulnerabilityService.MappingCreateResult.SUCCESS) {
            vulnerabilityFilterService.updateAllVulnerabilities();
            return success("Successfully created new mapping.");
        } else {
            return failure(result.toString());
        }
    }

    @RequestMapping(value="/createVulnerabilities", method = RequestMethod.POST)
    @ResponseBody
    public RestResponse<String> createVulnerabilities(@RequestParam String channelName,
                                                          @RequestParam String channelVulnerabilityCode) {

        ChannelVulnerabilityService.MappingCreateResult result =
                channelVulnerabilityService.createVulnerabilities(channelName, channelVulnerabilityCode);

        if (result == ChannelVulnerabilityService.MappingCreateResult.SUCCESS) {
            return success("Successfully created Vulnerabilities.");
        } else {
            return failure(result.toString());
        }
    }
}
