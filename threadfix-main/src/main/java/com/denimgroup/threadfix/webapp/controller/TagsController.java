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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.service.util.ControllerUtils;
import com.denimgroup.threadfix.service.util.PermissionUtils;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.webapp.config.FormRestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import org.codehaus.jackson.map.ObjectWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.io.IOException;
import java.util.*;

@Controller
@RequestMapping("/configuration/tags")
@PreAuthorize("hasRole('ROLE_CAN_MANAGE_TAGS')")
public class TagsController {

    @Autowired
    private TagService tagService;

    private final SanitizedLogger log = new SanitizedLogger(TagsController.class);
    private static final ObjectWriter WRITER = ControllerUtils.getObjectWriter(AllViews.RestViewTag.class);

    @RequestMapping(method = RequestMethod.GET)
    public String index(Model model) {
        return "tags/index";
    }

    @RequestMapping(value = "/map", method = RequestMethod.GET)
    public @ResponseBody RestResponse<Map<String, Object>> map() {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("tags", tagService.loadAll());
        return RestResponse.success(responseMap);
    }

    @RequestMapping(value = "/new", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Tag> newSubmit(@Valid @ModelAttribute Tag tag,
                                                     BindingResult result) {

        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {
            if (tag.getName().trim().equals("")) {
                result.rejectValue("name", null, null, "This field cannot be blank");
            } else {
                Tag databaseTag = tagService.loadTag(tag.getName().trim());
                if (databaseTag != null) {
                    result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
                }
            }

            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            log.info("Saving new Tag " + tag.getName());
            tagService.storeTag(tag);
            return RestResponse.success(tag);
        }
    }

    @RequestMapping(value = "/{tagId}/edit", method = RequestMethod.POST)
    public @ResponseBody RestResponse<List<Tag>> editSubmit(@PathVariable("tagId") int tagId, @Valid @ModelAttribute Tag tag,
                                                     BindingResult result) {
        if (result.hasErrors()) {
            return FormRestResponse.failure("error", result);
        } else {
            Tag databaseTag = null;
            if (tag.getName().trim().equals("")) {
                result.rejectValue("name", null, null, "This field cannot be blank");
            } else {
                databaseTag = tagService.loadTag(tag.getName().trim());
                if (databaseTag != null && !databaseTag.getId().equals(tagId)) {
                    result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
                }
                databaseTag = tagService.loadTag(tagId);
                if (databaseTag == null) {
                    result.rejectValue("name", MessageConstants.ERROR_INVALID, new String[]{"Tag Id"}, null);
                }
            }

            if (result.hasErrors()) {
                return FormRestResponse.failure("error", result);
            }

            if (databaseTag != null) {
                log.info("Editing Tag " + databaseTag.getName() + " to " + tag.getName());
                databaseTag.setName(tag.getName());
                tagService.storeTag(databaseTag);
                return RestResponse.success(tagService.loadAll());
            } else {
                return RestResponse.failure("Error occurs.");
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
        int numVulnComments = tag.getVulnerabilityComments().size();

        ModelAndView mav = new ModelAndView("tags/detail");
        mav.addObject("numApps", numApps);
        mav.addObject("numVulnComments", numVulnComments);
        mav.addObject(tag);
        return mav;
    }

    @RequestMapping(value = "/{tagId}/objects", method = RequestMethod.GET)
    public @ResponseBody String getAppList(@PathVariable("tagId") int tagId) throws IOException {

        Tag tag = tagService.loadTag(tagId);

        if (tag == null ) {
            log.warn("Tag Id is invalid.");
            return WRITER.writeValueAsString(RestResponse.failure("Tag Id is invalid."));
        }

        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put("appList", tag.getApplications());
        responseMap.put("numApps", tag.getApplications().size());
        responseMap.put("commentList", tag.getVulnerabilityComments());

        return WRITER.writeValueAsString(RestResponse.success(responseMap));
    }

}
