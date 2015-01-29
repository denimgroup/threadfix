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

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GraphConfig;
import com.denimgroup.threadfix.data.entities.VulnerabilitySearchParameters;
import com.denimgroup.threadfix.service.ApplicationChannelService;
import com.denimgroup.threadfix.service.ChannelTypeService;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.GraphConfigService;
import com.denimgroup.threadfix.service.VulnerabilitySearchService;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.validator.BeanValidator;
import org.codehaus.jackson.map.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.support.SessionStatus;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Controller
@RequestMapping("/graphConfig")
public class GraphConfigController {

    public GraphConfigController(){}

    private final SanitizedLogger log = new SanitizedLogger(GraphConfigController.class);
    private static final ObjectWriter writer = ControllerUtils.getObjectWriter(AllViews.TableRow.class);

    @Autowired
    private GraphConfigService graphConfigService;

   // @Autowired
    private GraphConfig graphConfig;

    @Autowired
    public VulnerabilitySearchService vulnerabilitySearchService;

    @Autowired
    public ChannelTypeService channelTypeService;

    @Autowired
    public ApplicationChannelService appChannelService;

    //@Autowired
    //public RealtimeMetaDataScanService realtimeScanService;

    @InitBinder
    public void initBinder(WebDataBinder dataBinder) {
        dataBinder.setValidator(new BeanValidator());
    }

    @RequestMapping(value = "/channels", method = RequestMethod.POST)
    public @ResponseBody void graphConfig(@ModelAttribute TableSortBean bean) throws IOException {
        List<ChannelType> scannerNames  = channelTypeService.loadAll();
        for(ChannelType scanName : scannerNames){
            String n = scanName.getName();
            graphConfig = new GraphConfig();
            graphConfig.setName(n);
            graphConfig.setAuditable(false);
            graphConfig.setInfoVulns(false);
            graphConfig.setLowVulns(false);
            graphConfig.setMediumVulns(false);
            graphConfig.setHighVulns(false);
            graphConfig.setCriticalVulns(false);
            processSubmit(graphConfig, null, null, null, null);
        }
    }

    @RequestMapping(value = "/data", method = RequestMethod.POST)
    public @ResponseBody String graphConfig() throws IOException {
        List<GraphConfig> scannerNames = graphConfigService.getScannerNames();
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("scanners", scannerNames);
        return writer.writeValueAsString(RestResponse.success(responseMap));
    }

    @RequestMapping(value = "/table", method = RequestMethod.POST)
    public @ResponseBody String searchVulnerabilities(@ModelAttribute VulnerabilitySearchParameters parameters) throws IOException {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("closed", vulnerabilitySearchService.performLookup(parameters));
        parameters.setShowClosed(false);
        parameters.setShowOpen(true);
        responseMap.put("open", vulnerabilitySearchService.performLookup(parameters));
        return writer.writeValueAsString(RestResponse.success(responseMap));
    }

    // TODO for fortify ssc
    /*
    @RequestMapping(value = "/remote/{appId}", method = RequestMethod.POST)
    public @ResponseBody String getRemoteProviders(@PathVariable("appId") Integer appId) throws IOException{
        ChannelType channelType = channelTypeService.loadChannel(ScannerType.FORTIFY_SSC_REALTIME.getFullName());
        ApplicationChannel appChannel = appChannelService.retrieveByAppIdAndChannelId(appId, channelType.getId());
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("remote", realtimeScanService.reteriveByApplicationChannelID(appChannel));
        return writer.writeValueAsString(RestResponse.success(responseMap));
    }*/

    @RequestMapping(method = RequestMethod.POST)
    public @ResponseBody String processSubmit(@Valid @ModelAttribute GraphConfig graphConfig,
                                              BindingResult result, SessionStatus status, Model model,
                                              HttpServletRequest request) throws IOException {
        ObjectWriter writer = ControllerUtils.getObjectWriter(AllViews.FormInfo.class);
        graphConfigService.storeGraphConfig(graphConfig);
        String user = SecurityContextHolder.getContext().getAuthentication().getName();
        log.debug("The graph configuration has been edited by user " + user);
        return writer.writeValueAsString(RestResponse.success("Saved"));
    }
}
