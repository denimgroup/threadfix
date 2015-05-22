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

package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.ScanImportStatus;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.importer.interop.ScanTypeCalculationService;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.ScanParametersBean;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest/applications")
public class ApplicationRestController extends TFRestController {

    public static final String
            CREATION_FAILED = "New Application creation failed.",
            APPLICATION_LOOKUP_FAILED = "Application lookup failed. Check your ID.",
            WAF_LOOKUP_FAILED = "WAF lookup failed. Check your ID.",
            ADD_CHANNEL_FAILED = "Adding an Application Channel failed.",
            SET_WAF_FAILED = "Call to setWaf failed.",
            SCAN_TYPE_LOOKUP_FAILED = "Unable to determine Scan type";

    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private DocumentService documentService;
    @Autowired
    private ScanService scanService;
    @Autowired
    private ScanParametersService scanParametersService;
    @Autowired
    private ScanTypeCalculationService scanTypeCalculationService;
    @Autowired
    private ScanMergeService scanMergeService;
    @Autowired
    private WafService wafService;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private ApplicationCriticalityService applicationCriticalityService;

    private final static String DETAIL = "applicationDetail",
            SET_PARAMS = "setParameters",
            LOOKUP = "applicationLookup",
            NEW = "newApplication",
            SET_WAF = "setWaf",
            UPLOAD = "uploadScan",
            ATTACH_FILE = "attachFile",
            SET_URL = "setUrl",
            UPDATE = "updateApplication";

    // TODO finalize which methods need to be restricted
    static {
        restrictedMethods.add(NEW);
        restrictedMethods.add(SET_WAF);
    }

    /**
     * Return details about a specific application.
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForApplicationById(String)
     *
     */
    @RequestMapping(headers="Accept=application/json", value="/{appId}", method=RequestMethod.GET)
    @JsonView(AllViews.RestViewApplication2_1.class)
    public Object applicationDetail(HttpServletRequest request,
                                                  @PathVariable("appId") int appId) throws IOException {
        log.info("Received REST request for Applications with id = " + appId + ".");

        String result = checkKey(request, DETAIL);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            log.warn(APPLICATION_LOOKUP_FAILED);
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        return RestResponse.success(application);
    }

    /**
     * Set scan parameters
     *
     * TODO add to ThreadFixRestClient
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#
     *
     */
    @RequestMapping(headers="Accept=application/json", value="/{appId}/attachFile", method=RequestMethod.POST)
    public RestResponse<String> attachFile(HttpServletRequest request,
                                         @PathVariable("appId") int appId,
                                         @RequestParam("file") MultipartFile file,
                                         @RequestParam("filename") String filename) {
        log.info("Received REST request to attach a file to application with id = " + appId + ".");

        String result = checkKey(request, ATTACH_FILE);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        if (filename != null) {
            documentService.saveFileToApp(appId, file, filename);
        } else {
            documentService.saveFileToApp(appId, file);
        }

        return success("Document was successfully uploaded.");
    }

    /**
     * Set scan parameters
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#setParameters(String, String, String)
     */
    @JsonView(AllViews.RestViewApplication2_1.class)
    @RequestMapping(headers="Accept=application/json", value="/{appId}/setParameters", method=RequestMethod.POST)
    public Object setParameters(HttpServletRequest request,
                                              @PathVariable("appId") int appId) throws IOException {
        log.info("Received REST request to set parameters for application with id = " + appId + ".");

        String result = checkKey(request, SET_PARAMS);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            log.warn(APPLICATION_LOOKUP_FAILED);
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        ScanParametersBean bean = new ScanParametersBean();

        if (request.getParameter("sourceCodeAccessLevel") != null) {
            bean.setSourceCodeAccessLevel(request.getParameter("sourceCodeAccessLevel"));
        }

        if (request.getParameter("frameworkType") != null) {
            bean.setApplicationType(request.getParameter("frameworkType"));
        }

        if (request.getParameter("repositoryUrl") != null) {
            bean.setSourceCodeUrl(request.getParameter("repositoryUrl"));
        }

        scanParametersService.saveConfiguration(application, bean);

        return RestResponse.success(application);
    }

    /**
     * Return details about a specific application.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForApplicationByName(String, String)
     */
    @RequestMapping(headers="Accept=application/json", value="/{teamId}/lookup", method=RequestMethod.GET)
    public Object applicationLookup(HttpServletRequest request,
                                    @PathVariable("teamId") String teamName) throws IOException {
        String appName = request.getParameter("name");
        String appUniqueId = request.getParameter("uniqueId");

        String result = checkKey(request, LOOKUP);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }
        if ((appName == null) && (appUniqueId == null)) {
            return failure(APPLICATION_LOOKUP_FAILED);
        }
        log.info("Received REST request for Applications in team = " + teamName + ".");
        Organization org = organizationService.loadByName(teamName);
        if (org == null) {
            log.warn(APPLICATION_LOOKUP_FAILED);

            // In case Go encodes spaces to '+'
            if (teamName.contains("+")) {
                teamName = teamName.replace("+", " ");
                log.info("Trying to look up again for Applications in team = " + teamName + ".");
                org = organizationService.loadByName(teamName);
            }

            if (org == null)
                return failure(APPLICATION_LOOKUP_FAILED);
        }
        Application application = null;
        int teamId = org.getId();
        if (appName != null)
            application = applicationService.loadApplication(appName, teamId);
        if (appUniqueId != null)
            application = applicationService.loadApplicationByUniqueId(appUniqueId, teamId);

        if (application == null) {
            if ((appName != null) && (appName.contains("+"))) {
                appName = appName.replace("+", " ");
                application = applicationService.loadApplication(appName, teamId);
            }
            if ((appUniqueId != null) && (appUniqueId.contains("+"))) {
                appUniqueId = appUniqueId.replace("+", " ");
                application = applicationService.loadApplicationByUniqueId(appUniqueId, teamId);
            }
            if (application == null) {
                log.warn(APPLICATION_LOOKUP_FAILED);
                return failure(APPLICATION_LOOKUP_FAILED);
            }
        }

        return RestResponse.success(application);
    }

    /**
     * Allows the user to upload a scan to an existing application channel.
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#uploadScan(String, String)
     *
     * @return Status response. We may change this to make it more useful.
     */
    @RequestMapping(headers="Accept=application/json", value="/{appId}/upload", method=RequestMethod.POST)
    @JsonView(AllViews.RestViewScan2_1.class)
    public Object uploadScan(@PathVariable("appId") int appId,
                             HttpServletRequest request,
                             @RequestParam("file") MultipartFile file) throws IOException {
        log.info("Received REST request to upload a scan to application " + appId + ".");

        String result = checkKey(request, UPLOAD);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Integer myChannelId = scanTypeCalculationService.calculateScanType(appId, file, request.getParameter("channelId"));

        if (myChannelId == null) {
            return failure(SCAN_TYPE_LOOKUP_FAILED);
        }

        String fileName = scanTypeCalculationService.saveFile(myChannelId, file);

        ScanCheckResultBean returnValue = scanService.checkFile(myChannelId, fileName);

        if (ScanImportStatus.SUCCESSFUL_SCAN == returnValue.getScanCheckResult()) {
            Scan scan = scanMergeService.saveRemoteScanAndRun(myChannelId, fileName);
            return RestResponse.success(scan);
        } else {
            return failure(returnValue.getScanCheckResult().toString());
        }
    }

    /**
     * Overwrites the WAF for the application.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#addWaf(String, String)
     *
     */
    @JsonView(AllViews.RestViewApplication2_1.class)
    @RequestMapping(headers="Accept=application/json", value="/{appId}/setWaf", method=RequestMethod.POST)
    public Object setWaf(HttpServletRequest request,
                         @PathVariable("appId") int appId) throws IOException {

        String idString = request.getParameter("wafId");

        Integer wafId = null;

        if (idString != null) {
            try {
                wafId = Integer.valueOf(idString);
            } catch (NumberFormatException e) {
                log.warn("Non-integer parameter was submitted to setWaf.");
            }
            if (wafId != null) {
                log.info("Received REST request to add WAF " + wafId + " to Application " + appId + ".");
            }
        }

        String result = checkKey(request, SET_WAF);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        if (wafId == null) {
            log.warn("Received incomplete REST request to add a WAF");
            return failure(WAF_LOOKUP_FAILED);
        }

        Application application = applicationService.loadApplication(appId);
        Waf waf = wafService.loadWaf(wafId);

        if (application == null) {
            log.warn(APPLICATION_LOOKUP_FAILED);
            return failure(APPLICATION_LOOKUP_FAILED);
        } else if (waf == null) {
            log.warn(WAF_LOOKUP_FAILED);
            return failure(WAF_LOOKUP_FAILED);
        } else {

            // Delete WAF rules if the WAF has changed
            Integer oldWafId = null;

            if (application.getWaf() != null && application.getWaf().getId() != null) {
                oldWafId = application.getWaf().getId();
            }

            application.setWaf(waf);
            applicationService.updateWafRules(application, oldWafId);
            applicationService.storeApplication(application);
            return RestResponse.success(application);
        }
    }


    /**
     * Set the URL for the application.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#addAppUrl(String, String)
     *
     */
    @RequestMapping(headers="Accept=application/json", value="/{appId}/addUrl", method=RequestMethod.POST)
    @JsonView(AllViews.RestViewApplication2_1.class)
    public Object setUrl(HttpServletRequest request,
                         @PathVariable("appId") int appId) throws IOException {

        String url = request.getParameter("url");

        String result = checkKey(request, SET_URL);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        
        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            log.warn("Invalid Application ID.");
            return failure(APPLICATION_LOOKUP_FAILED);
        } else {
            application.setUrl(url);
            applicationService.storeApplication(application);
            return RestResponse.success(application);
        }
    }

    @RequestMapping(value = "/{appId}/update", method = RequestMethod.PUT, consumes = "application/x-www-form-urlencoded")
    public Object updateApplication(@PathVariable("appId") Integer appId,
                                    @RequestBody MultiValueMap<String, String> params,
                                    Application application,
                                    BindingResult bindingResult, HttpServletRequest request) {

        log.info("Received REST request for updating Application with id = " + appId + ".");

        String result = checkKey(request, UPDATE);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        if(params == null || params.isEmpty()){
            return failure("No parameters have been set");
        }

        try {
            return applicationService.updateApplicationFromREST(appId, params, bindingResult);
        }catch (RuntimeException e){
            return FormRestResponse.failure(e.getMessage(), bindingResult);
        }
    }
}
