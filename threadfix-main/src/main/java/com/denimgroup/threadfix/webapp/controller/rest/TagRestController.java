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

import com.denimgroup.threadfix.data.entities.Tag;
import com.denimgroup.threadfix.data.enums.TagType;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.views.AllViews;
import com.denimgroup.threadfix.views.AllViews.RestViewTag;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest/tags")
public class TagRestController extends TFRestController {

    @Autowired
    private TagService tagService;

    private final static String DETAIL = "tagIDLookup",
            LOOKUP                     = "tagNameLookup",
            NEW                        = "newTag",
            INDEX                      = "tagList";
    private static final String LIST = "list";
    private static final String UPDATE = "updateTag";
    private static final String DELETE = "deleteTag";
    private static final String LIST_APPLICATIONS = "listApplications";

    private static final String
            TAG_LOOKUP_FAILED = "Tag lookup failed. Check your parameters.";

    static {
        restrictedMethods.add(NEW);
    }

    /**
     * Create a new tag.
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#createTag(String name, String tagType)
     *
     */
    @RequestMapping(headers="Accept=application/json", value="/new", method=RequestMethod.POST)
    @JsonView(AllViews.RestView2_1.class)
    public Object createTag(HttpServletRequest request) {
        log.info("Received REST request for a new tag.");

        String result = checkKey(request, NEW);
        if (!result.equals(API_KEY_SUCCESS)) {
            return RestResponse.failure(result);
        }

        String name = request.getParameter("name");
        String tagType = request.getParameter("tagType");
        TagType tagTypeEnum = TagType.getTagType(tagType);
        // Default tag is Application
        if (tagTypeEnum == null)
            tagTypeEnum = TagType.APPLICATION;

        if (name == null || name.trim().equals(""))
            return RestResponse.failure("This field cannot be blank");

        Tag newTag = new Tag();
        newTag.setName(name);
        newTag.setType(tagTypeEnum);

        Tag databaseTag;
        if (!newTag.getTagForComment())
            databaseTag = tagService.loadApplicationTag(newTag.getName().trim());
        else
            databaseTag = tagService.loadCommentTag(newTag.getName().trim());
        if (databaseTag != null) {
            return RestResponse.failure("The name is already taken.");
        }

        log.info("Saving new Tag " + newTag.getName());
        tagService.storeTag(newTag);
        return RestResponse.success(newTag);
    }

    /**
     * Return details about a specific application.
     *
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchTagById(String id)
     *
     */
    @RequestMapping(headers="Accept=application/json", value="/{tagId}", method=RequestMethod.GET)
    @JsonView(AllViews.RestViewApplication2_1.class)
    public Object tagDetail(HttpServletRequest request,
                            @PathVariable("tagId") int tagId) {
        log.info("Received REST request for tag with id = " + tagId + ".");

        String result = checkKey(request, DETAIL);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Tag tag = tagService.loadTag(tagId);

        if (tag == null) {
            log.warn(TAG_LOOKUP_FAILED);
            return failure(TAG_LOOKUP_FAILED);
        }

        return RestResponse.success(tag);
    }

    /**
     * Return details about a specific tag.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#searchTagsByName(String name)
     */
    @RequestMapping(headers="Accept=application/json", value="/lookup", method=RequestMethod.GET)
    public Object tagLookup(HttpServletRequest request) {
        String tagName = request.getParameter("name");

        String result = checkKey(request, LOOKUP);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }
        if ((tagName == null)) {
            return failure(TAG_LOOKUP_FAILED);
        }
        log.info("Received REST request for Tag " + tagName + ".");
        List<Tag> tags = tagService.loadTagsByName(tagName);

        if (tags == null)
            return failure(TAG_LOOKUP_FAILED);

        return RestResponse.success(tags);
    }

    /**
     * Return all active tags.
     * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#getAllTags()
     */
    @RequestMapping(headers="Accept=application/json", value="/index", method=RequestMethod.GET)
    public Object index(HttpServletRequest request) {

        String result = checkKey(request, INDEX);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }
        log.info("Received REST request to query all tags.");
        Map<String, Object> map = map();
        map.put("Application Tag", tagService.loadAllApplicationTags());
        map.put("Vulnerability Tag", tagService.loadAllVulnTags());
        map.put("Vulnerability Comment Tag", tagService.loadAllCommentTags());

        return RestResponse.success(map);
    }

    @RequestMapping(value = "/list", method = RequestMethod.GET, headers = "Accept=application/json")
    @JsonView(RestViewTag.class)
    public Object list(HttpServletRequest request){

        log.info("Received REST request for Tag list.");

        String result = checkKey(request, LIST);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        List<Tag> tags = tagService.loadAll();

        return success(tags);
    }

    @RequestMapping(value = "/{tagId}/update", method = RequestMethod.POST, headers = "Accept=application/json")
    @JsonView(RestViewTag.class)
    public Object updateTag(@PathVariable("tagId") Integer tagId, @RequestParam("name") String tagName, HttpServletRequest request){

        log.info("Received REST request for updating an existing Tag.");

        String result = checkKey(request, UPDATE);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        if(tagName == null || tagName.trim().isEmpty()){
            return failure("Name is required");
        }

        Tag existingTag = tagService.loadApplicationTag(tagName);

        if(existingTag != null && !tagId.equals(existingTag.getId())){
            return failure("Name is already taken by another tag");
        }

        Tag tag = tagService.loadTag(tagId);

        if(tag == null){
            return failure("No tag exists for id: " + tagId);
        }

        tag.setName(tagName);

        tagService.storeTag(tag);

        return success(tag);
    }

    @RequestMapping(value = "/{tagId}/delete", method = RequestMethod.POST, headers = "Accept=application/json")
    public Object deleteTag(@PathVariable("tagId") Integer tagId, HttpServletRequest request){

        log.info("Received REST request for deleting an existing Tag.");

        String result = checkKey(request, DELETE);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Tag tag = tagService.loadTag(tagId);

        if(tag != null && tag.getDeletable()){
            tagService.deleteById(tagId);
            return success("Tag deleted successfully");
        }else{
            return failure("Tag Id is invalid or Tag currently can not be deleted.");
        }
    }

    @RequestMapping(value = "/{tagId}/listApplications", method = RequestMethod.GET, headers = "Accept=application/json")
    @JsonView(RestViewTag.class)
    public Object listApplications(@PathVariable("tagId") Integer tagId, HttpServletRequest request){

        log.info("Received REST request for listing Applications with a Tag.");

        String result = checkKey(request, LIST_APPLICATIONS);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        Tag tag = tagService.loadTag(tagId);

        if(tag == null){
            return failure("No tag exists for id: " + tagId);
        }

        return success(tag.getApplications());
    }
}
