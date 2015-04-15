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
package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Tag;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.ApplicationService;
import com.denimgroup.threadfix.service.OrganizationService;
import com.denimgroup.threadfix.service.TagService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * This is a QA only class so we can skip steps while testing
 *
 * Created by daniel on 11/24/14.
 */

@Controller
@RequestMapping("/rest/tag")
public class TagRestController {

    @Autowired
    TagService tagService;
    @Autowired
    ApplicationService applicationService;
    @Autowired
    OrganizationService organizationService;

    @RequestMapping(value = "create", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Tag> createTag(@RequestParam String tagname) {
        Tag tag = new Tag();

        tag.setName(tagname);

        tagService.storeTag(tag);

        return success(tag);
    }

    @RequestMapping(value = "attach", method = RequestMethod.POST)
    public @ResponseBody RestResponse<Tag> attachApp(@RequestParam String tagname,
                                                     @RequestParam String appname,
                                                     @RequestParam String teamname) {
        Tag tag = tagService.loadTag(tagname);

        Application application = applicationService.loadApplication(appname, organizationService.loadByName(teamname).getId());
        List<Tag> tagList = application.getTags();

        if (!tagList.contains(tag)) {
            tagList.add(tag);
        }

        application.setTags(tagList);

        applicationService.storeApplication(application);

        return success(tag);
    }
}
