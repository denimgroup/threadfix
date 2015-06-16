package com.denimgroup.threadfix.webapp.controller.rest;

import com.denimgroup.threadfix.data.entities.Tag;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.views.AllViews.RestViewTag;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

@RestController
@RequestMapping("/rest/tags")
public class TagRestController extends TFRestController {

    private static final String NEW = "newTag";
    private static final String LIST = "list";
    private static final String UPDATE = "updateTag";
    private static final String DELETE = "deleteTag";
    private static final String LIST_APPLICATIONS = "listApplications";

    @Autowired
    private TagService tagService;

    @RequestMapping(value = "/new", method = RequestMethod.POST, headers = "Accept=application/json")
    @JsonView(RestViewTag.class)
    public Object newTag(@RequestParam("name") String tagName, HttpServletRequest request){

        log.info("Received REST request for a new Tag.");

        String result = checkKey(request, NEW);
        if (!result.equals(API_KEY_SUCCESS)) {
            return failure(result);
        }

        if(tagName == null || tagName.trim().isEmpty()){
            return failure("Name is required");
        }

        Tag dbTag = tagService.loadApplicationTag(tagName);

        if (dbTag != null){
            return failure("Name is already taken by another tag");
        }

        Tag tag = new Tag();
        tag.setName(tagName);
        tag.setTagForComment(false);

        tagService.storeTag(tag);

        return success(tag);
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
