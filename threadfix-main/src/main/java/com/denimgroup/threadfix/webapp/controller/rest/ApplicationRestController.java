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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Tag;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.data.enums.TagType;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.*;
import com.denimgroup.threadfix.service.beans.ScanParametersBean;
import com.denimgroup.threadfix.util.Result;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartRequest;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.resultError;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;
import static com.denimgroup.threadfix.webapp.controller.rest.RestMethod.*;

@RestController
@RequestMapping("/rest/applications")
public class ApplicationRestController extends TFRestController {

    public static final String
            APPLICATION_LOOKUP_FAILED = "Application lookup failed. Check your ID.",
            WAF_LOOKUP_FAILED = "WAF lookup failed. Check your ID.",
            TAG_LOOKUP_FAILED = "Tag lookup failed. Check your ID.",
            TAG_INVALID = "Invalid Tag ID. It is not an Application Tag.",
    APPLICATION_LOOKUP_INVALID = "More than one application found. Check your search criteria.";

    @Autowired
    private ApplicationService applicationService;
    @Autowired
    private DocumentService documentService;
    @Autowired
    private ScanParametersService scanParametersService;
    @Autowired
    private WafService wafService;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private TagService tagService;
    @Autowired
    private UploadScanService uploadScanService;

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
        LOG.info("Received REST request for Applications with id = " + appId + ".");

        Result<String> keyCheck = checkKey(request, RestMethod.APPLICATION_DETAIL, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            LOG.warn(APPLICATION_LOOKUP_FAILED);
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
        LOG.info("Received REST request to attach a file to application with id = " + appId + ".");

        Result<String> keyCheck = checkKey(request, APPLICATION_ATTACH_FILE, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
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
        LOG.info("Received REST request to set parameters for application with id = " + appId + ".");

        Result<String> keyCheck = checkKey(request, APPLICATION_SET_PARAMS, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            LOG.warn(APPLICATION_LOOKUP_FAILED);
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

        String result = scanParametersService.saveConfiguration(application, bean);
        if (result == null)
            return RestResponse.success(application);
        else return RestResponse.failure(result);
    }

    /**
     * Return details about a specific application.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForApplicationByName(String, String)
     */
    @JsonView(AllViews.RestViewApplication2_1.class)
    @RequestMapping(headers="Accept=application/json", value="/{teamId}/lookup", method=RequestMethod.GET)
    public Object applicationLookup(HttpServletRequest request,
                                    @PathVariable("teamId") String teamName) throws IOException {
        String appName = request.getParameter("name");
        String appUniqueId = request.getParameter("uniqueId");

        // we check again after the application lookup to see if the user actually has permissions
        Result<String> keyCheck = checkKeyGlobal(request, APPLICATION_LOOKUP);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }
        if ((appName == null) && (appUniqueId == null)) {
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        LOG.info("Received REST request for Applications in team = " + teamName + ".");
        Organization org = organizationService.loadByName(teamName);
        if (org == null) {
            LOG.warn(APPLICATION_LOOKUP_FAILED);

            // In case Go encodes spaces to '+'
            if (teamName.contains("+")) {
                teamName = teamName.replace("+", " ");
                LOG.info("Trying to look up again for Applications in team = " + teamName + ".");
                org = organizationService.loadByName(teamName);
            }

            if (org == null)
                return failure(APPLICATION_LOOKUP_FAILED);
        }

        Application application = null;
        int teamId = org.getId();
        if (appName != null)
            application = applicationService.loadApplication(appName, teamId);
        if (appUniqueId != null) {
            List<Application> applicationList = applicationService.loadApplicationByUniqueId(appUniqueId, teamId);
            if (applicationList != null && applicationList.size() > 0) {
                if (applicationList.size() > 1) {
                    return failure(APPLICATION_LOOKUP_INVALID);
                }
                application = applicationList.get(0);
            }
        }

        if (application == null) {
            if ((appName != null) && (appName.contains("+"))) {
                appName = appName.replace("+", " ");
                application = applicationService.loadApplication(appName, teamId);
            }
            if ((appUniqueId != null) && (appUniqueId.contains("+"))) {
                appUniqueId = appUniqueId.replace("+", " ");

                List<Application> applicationList = applicationService.loadApplicationByUniqueId(appUniqueId, teamId);
                if (applicationList != null && applicationList.size() > 0) {
                    if (applicationList.size() > 1) {
                        return failure(APPLICATION_LOOKUP_INVALID);
                    }
                    application = applicationList.get(0);
                }
            }
            if (application == null) {
                LOG.warn(APPLICATION_LOOKUP_FAILED);
                return failure(APPLICATION_LOOKUP_FAILED);
            }
        }

        keyCheck = checkKey(request, APPLICATION_LOOKUP, teamId, application.getId());
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        return RestResponse.success(application);
    }


    /**
     * Return details about applications.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchForApplicationsByUniqueId(String)
     */
    @JsonView(AllViews.RestViewApplication2_1.class)
    @RequestMapping(headers="Accept=application/json", value="/allTeamLookup", method=RequestMethod.GET)
    public Object applicationLookupInAllTeam(HttpServletRequest request) throws IOException {
        String appUniqueId = request.getParameter("uniqueId");

        // we check again after the application lookup to see if the user actually has permissions
        Result<String> keyCheck = checkKeyGlobal(request, APPLICATION_LOOKUP);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }
        if (appUniqueId == null) {
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        LOG.info("Received REST request for Applications.");

        List<Application> applicationList = list();
        if (appUniqueId != null) {
            applicationList = applicationService.loadApplicationByUniqueId(appUniqueId, -1);
        }

        if (applicationList == null || applicationList.isEmpty()) {
            if ((appUniqueId != null) && (appUniqueId.contains("+"))) {
                appUniqueId = appUniqueId.replace("+", " ");

                applicationList = applicationService.loadApplicationByUniqueId(appUniqueId, -1);
            }
            if (applicationList == null || applicationList.isEmpty()) {
                LOG.warn(APPLICATION_LOOKUP_FAILED);
                return failure(APPLICATION_LOOKUP_FAILED);
            }
        }

        List<Application> resultList = list();
        for (Application application: applicationList) {
            keyCheck = checkKey(request, APPLICATION_LOOKUP, application.getOrganization().getId(), application.getId());
            if (keyCheck.success()) {
                resultList.add(application);
            }
        }

        return RestResponse.success(resultList);
    }


    /**
     * Allows the user to upload a scan to an existing application channel.
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#uploadScan(String, String)
     *
     * @return Status response. We may change this to make it more useful.
     */
    @RequestMapping(headers="Accept=application/json", value="/{appId}/upload/multi", method=RequestMethod.POST)
    @JsonView(AllViews.RestViewScan2_1.class)
    public Object uploadScans(@PathVariable("appId") int appId,
                             HttpServletRequest request,
                             MultipartRequest multiPartRequest) throws IOException {
        LOG.info("Received REST request to upload multiple scans to application " + appId + ".");

        Result<String> keyCheck = checkKey(request, APPLICATION_UPLOAD, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);
        if (application == null) {
            return failure("Invalid application ID.");
        }

        MultiValueMap<String, MultipartFile> fileMap = multiPartRequest.getMultiFileMap();

        List<MultipartFile> fileList = list();

        if (!fileMap.isEmpty()) {
            for(List<MultipartFile> subList : fileMap.values()){
                fileList.addAll(subList);
            }
        }

        return uploadScanService.processMultiFileUpload(fileList, null, appId, request.getParameter("channelId"), false);
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
        LOG.info("Received REST request to upload a scan to application " + appId + ".");

        Result<String> keyCheck = checkKey(request, APPLICATION_UPLOAD, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);
        if (application == null) {
            return failure("Invalid application ID.");
        }

        return uploadScanService.processMultiFileUpload(list(file), null, appId, request.getParameter("channelId"), false);
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
                LOG.warn("Non-integer parameter was submitted to setWaf.");
            }
            if (wafId != null) {
                LOG.info("Received REST request to add WAF " + wafId + " to Application " + appId + ".");
            }
        }

        Result<String> keyCheck = checkKey(request, APPLICATION_SET_WAF, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        if (wafId == null) {
            LOG.warn("Received incomplete REST request to add a WAF");
            return failure(WAF_LOOKUP_FAILED);
        }

        Application application = applicationService.loadApplication(appId);
        Waf waf = wafService.loadWaf(wafId);

        if (application == null) {
            LOG.warn(APPLICATION_LOOKUP_FAILED);
            return failure(APPLICATION_LOOKUP_FAILED);
        } else if (waf == null) {
            LOG.warn(WAF_LOOKUP_FAILED);
            return failure(WAF_LOOKUP_FAILED);
        } else {

            // Delete WAF rules if the WAF has changed
            Integer oldWafId = null;

            if (application.getWaf() != null && application.getWaf().getId() != null) {
                oldWafId = application.getWaf().getId();
            }

            application.setWaf(waf);
            applicationService.updateWafRules(application, oldWafId);
            applicationService.storeApplication(application, EventAction.APPLICATION_EDIT);
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

        Result<String> keyCheck = checkKey(request, APPLICATION_SET_URL, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }
        
        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            LOG.warn("Invalid Application ID.");
            return failure(APPLICATION_LOOKUP_FAILED);
        } else {
            application.setUrl(url);
            applicationService.storeApplication(application, EventAction.APPLICATION_EDIT);
            return RestResponse.success(application);
        }
    }

    @RequestMapping(value = "/{appId}/update", method = RequestMethod.PUT, consumes = "application/x-www-form-urlencoded")
    public Object updateApplication(@PathVariable("appId") Integer appId,
                                    @RequestBody MultiValueMap<String, String> params,
                                    Application application,
                                    BindingResult bindingResult, HttpServletRequest request) {

        LOG.info("Received REST request for updating Application with id = " + appId + ".");

        Result<String> keyCheck = checkKey(request, APPLICATION_UPDATE, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
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


    @RequestMapping(value = "/{appId}/tags/add/{tagId}", method = RequestMethod.POST, headers="Accept=application/json")
    @JsonView(AllViews.RestViewTag.class)
    public Object addTag(@PathVariable("appId") Integer appId, @PathVariable("tagId") Integer tagId,
                         HttpServletRequest request){

            LOG.info("Received REST request adding Tag " + tagId + " for Application " + appId + ".");
        Result<String> keyCheck = checkKey(request, APPLICATION_ADD_TAG, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if(application == null){
            LOG.warn("Invalid Application ID.");
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        Tag tag = tagService.loadTag(tagId);

        if(tag == null){
            LOG.warn("Invalid Tag ID.");
            return failure(TAG_LOOKUP_FAILED);
        }

        if (tag.getType() != null && TagType.APPLICATION != tag.getType()) {
            LOG.warn(TAG_INVALID);
            return failure(TAG_INVALID);
        }

        if(application.containTag(tag)){
            LOG.warn("Tag has already been set on this application");
            return failure("Tag has already been set on this application");
        }

        application.getTags().add(tag);
        applicationService.storeApplication(application, EventAction.APPLICATION_SET_TAGS);

        return success(application);
    }

    /**
     * Remove tag from application.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#removeAppTag(String appId, String tagId)
     *
     */
    @RequestMapping(value = "/{appId}/tags/remove/{tagId}",
            method = RequestMethod.POST,
            headers="Accept=application/json")
    @JsonView(AllViews.RestViewApplication2_1.class)
    public Object removeTag(HttpServletRequest request,
                         @PathVariable("appId") int appId,
                         @PathVariable("tagId") int tagId) throws IOException {

        LOG.info("Received REST request removing Tag " + tagId + " from Application " + appId + ".");
        Result<String> keyCheck = checkKey(request, APPLICATION_REMOVE_TAG, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if(application == null){
            LOG.warn("Invalid Application ID.");
            return failure(APPLICATION_LOOKUP_FAILED);
        }

        Tag tag = tagService.loadTag(tagId);

        if(tag == null){
            LOG.warn("Invalid Tag ID.");
            return failure(TAG_LOOKUP_FAILED);
        }

        if(application.containTag(tag)){
            application.getTags().remove(tag);
            applicationService.storeApplication(application, EventAction.APPLICATION_SET_TAGS);

            return success("Tag successfully removed from application");
        }else{
            return failure("Tag no present on this application");
        }
    }

    @RequestMapping(headers="Accept=application/json", value="/{appId}/scans", method=RequestMethod.GET)
    @JsonView(AllViews.RestViewScanList.class)
    public Object scanList(HttpServletRequest request,
                           @PathVariable("appId") int appId) throws IOException {

        Result<String> keyCheck = checkKey(request, APPLICATION_SCAN_LIST, -1, appId);
        if (!keyCheck.success()) {
            return resultError(keyCheck);
        }

        Application application = applicationService.loadApplication(appId);

        if (application == null) {
            LOG.warn("Invalid Application ID.");
            return failure(APPLICATION_LOOKUP_FAILED);
        } else if (application.getScans() == null || application.getScans().isEmpty()) {
            String message = "No scans associated with application: " + appId;
            LOG.warn(message);
            return failure(message);
        } else {
            return success(application.getScans());
        }
    }
}
