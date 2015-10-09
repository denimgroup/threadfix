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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.EventAction;
import com.denimgroup.threadfix.data.enums.TagType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/configuration/tags")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TAGS')")
public class TagsController {

    @Autowired
    private TagService tagService;
    @Autowired
    private OrganizationService organizationService;
    @Autowired
    private ApplicationService applicationService;

    private final SanitizedLogger log = new SanitizedLogger(TagsController.class);

    @RequestMapping(method = RequestMethod.GET)
    public String index() {
        log.info("Directing to tags index page.");
        return "tags/index";
    }

    @RequestMapping(value = "/batchTagging/{tagIds}", method = RequestMethod.GET)
    public String batchTagging(@PathVariable("tagIds") String tagIds, Model model) {
        log.info("Directing to batch tagging page.");
        model.addAttribute("tagIds", tagIds);
        return "tags/batchTagging";
    }

    @RequestMapping(value = "/map", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> map() {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("tags", tagService.loadAllApplicationTags());
        responseMap.put("vulnTags", tagService.loadAllVulnTags());
        responseMap.put("commentTags", tagService.loadAllCommentTags());
        responseMap.put("tagTypes", TagType.values());
        return RestResponse.success(responseMap);
    }

    @JsonView(AllViews.VulnSearchApplications.class)
    @RequestMapping(value = "/batchTagging/map", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> batchTaggingMap() {
        Map<String, Object> responseMap = new HashMap<>();
        List<Organization> teams = organizationService.loadAllActiveFilter();
        responseMap.put("tags", tagService.loadAllApplicationTags());
        responseMap.put("applications", PermissionUtils.filterAppsList(teams));
        return RestResponse.success(responseMap);
    }

    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Tag> newSubmit(@Valid @ModelAttribute Tag tag,
                                                     BindingResult result) {

        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {

            tagService.validate(tag, result);

            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            log.info("Saving new " + tag.getType() + " tag " + tag.getName());
            tagService.storeTag(tag);
            return RestResponse.success(tag);
        }
    }

    @RequestMapping(value = "/{tagId}/edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Map<String, Object>> editSubmit(@PathVariable("tagId") int tagId, @Valid @ModelAttribute Tag tag,
                                                     BindingResult result) {
        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {
            tagService.validate(tag, result);

            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            Tag databaseTag = tagService.loadTag(tagId);
            if (databaseTag != null) {
                Map<String, Object> resultMap = new HashMap<>();
                log.info("Editing Tag " + databaseTag.getName() + " to " + tag.getName());
                databaseTag.setName(tag.getName());
                tagService.storeTag(databaseTag);
                resultMap.put("tags", tagService.loadAllApplicationTags());
                resultMap.put("vulnTags", tagService.loadAllVulnTags());
                resultMap.put("commentTags", tagService.loadAllCommentTags());
                return RestResponse.success(resultMap);
            } else {
                return RestResponse.failure("Invalid TagId.");
            }
        }
    }

    @RequestMapping(value = "/{tagId}/delete", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Tag> deleteSubmit(@PathVariable("tagId") int tagId) {
        Tag tag = tagService.loadTag(tagId);

        if (tag != null && tag.getDeletable()) {
            tagService.deleteById(tagId);
            return RestResponse.success(null);
        } else {
            log.warn("Tag Id is invalid or Tag currently can not be deleted.");
            return RestResponse.failure("Tag Id is invalid or Tag currently can not be deleted.");
        }
    }

    @RequestMapping(value = "/{tagId}/view", method = RequestMethod.GET)
    public ModelAndView viewDetailTag(@PathVariable("tagId") int tagId) {

        Tag tag = tagService.loadTag(tagId);

        if (tag == null ) {
            log.warn("Tag Id is invalid.");
            return new ModelAndView("redirect:/configuration/tags");
        }

        int numApps = tag.getApplications().size();

        ModelAndView mav = new ModelAndView("tags/detail");
        mav.addObject("numApps", numApps);
        mav.addObject("numVulns", tag.getVulnerabilities().size());
        mav.addObject("numVulnComments", tag.getVulnCommentsCount());
        mav.addObject(tag);
        return mav;
    }

    @JsonView(AllViews.VulnerabilityDetail.class)
    @RequestMapping(value = "/{tagId}/objects", method = RequestMethod.GET)
    public @ResponseBody Object getTagList(@PathVariable("tagId") int tagId) throws IOException {

        Tag tag = tagService.loadTag(tagId);

        if (tag == null ) {
            log.warn("Tag Id is invalid.");
            return RestResponse.failure("Tag Id is invalid.");
        }

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("appList", tag.getApplications());
        responseMap.put("numApps", tag.getApplications().size());
        responseMap.put("vulnList", tag.getVulnerabilities());
        responseMap.put("commentList", tag.getVulnerabilityComments());
        responseMap.put("type", tag.getType());

        return RestResponse.success(responseMap);
    }

    @RequestMapping(value = "/batchTagging/submit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<String> submitBatchTagging(@Valid @ModelAttribute BatchTaggingParameters batchTaggingParameters) {

        List<Application> applications = batchTaggingParameters.getApplications();
        List<Tag> tags = batchTaggingParameters.getTags();

        tags = tagService.setEnterpriseTag(tags);

        log.info("About to add " + tags.size() + " tags to " + applications.size() + " applications.");
        for (Application application: applications) {
            Application dbApp = applicationService.loadApplication(application.getId());
            if (dbApp == null) {
                log.warn("Unable to find application with ID " + application.getId());
                RestResponse.failure("Application selected is invalid.");
            }

            if (!PermissionUtils.isAuthorized(Permission.CAN_MANAGE_APPLICATIONS, dbApp.getOrganization().getId(), dbApp.getId())) {
                RestResponse.failure("You do not have permission to manage application " + application.getName() + ".");
            }

            List<Tag> allAppTags = tagService.loadAllApplicationTags();

            for (Tag tag: tags) {
                if (!isValidTag(allAppTags, tag)) {
                    log.warn("Unable to find tag with ID " + tag.getId());
                    RestResponse.failure("Tag selected is invalid.");
                }
                if (!dbApp.containTag(tag)) {
                    dbApp.getTags().add(tag);
                    log.info("Add tag " + tag.getName() + " to application " + dbApp.getName() + ".");
                } else
                    log.info("Tag " + tag.getName() + " was already added to application " + dbApp.getName() + ".");
            }
            applicationService.storeApplication(dbApp, EventAction.APPLICATION_SET_TAGS);
        }

        return RestResponse.success("Batch tagging ran successfully.");
    }

    private boolean isValidTag(List<Tag> tags, Tag tag) {
        for (Tag appTag: tags) {
            if (appTag.getId().compareTo(tag.getId()) == 0)
                return true;
        }
        return false;
    }

}
