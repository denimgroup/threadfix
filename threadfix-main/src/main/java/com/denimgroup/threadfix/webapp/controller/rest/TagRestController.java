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
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.service.TagService;
import com.denimgroup.threadfix.views.AllViews;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;

@RestController
@RequestMapping("/rest/tags")
public class TagRestController extends TFRestController {

	@Autowired
	private TagService tagService;

	private final static String DETAIL = "tagIDLookup",
			LOOKUP                     = "tagNameLookup",
			NEW                        = "newTag",
			INDEX                      = "tagList";

	private static final String
			TAG_LOOKUP_FAILED = "Tag lookup failed. Check your parameters.";

	static {
		restrictedMethods.add(NEW);
	}

	/**
	 * Create a new tag.
	 *
	 * @see com.denimgroup.threadfix.remote.ThreadFixRestClient#createTag(String name, Boolean isCommentTag)
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
		String isCommentTag = request.getParameter("isCommentTag");

		if (name == null || name.trim().equals(""))
			return RestResponse.failure("This field cannot be blank");

		Tag newTag = new Tag();
		newTag.setName(name);
		newTag.setTagForComment(Boolean.parseBoolean(isCommentTag));

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
	public Object applicationLookup(HttpServletRequest request) {
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
		map.put("Vulnerability Comment Tag", tagService.loadAllCommentTags());

		return RestResponse.success(map);
	}
}
