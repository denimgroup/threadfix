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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.CollectionUtils;
import com.denimgroup.threadfix.data.dao.TagDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityCommentDao;
import com.denimgroup.threadfix.data.entities.Tag;
import com.denimgroup.threadfix.data.entities.VulnerabilityComment;
import com.denimgroup.threadfix.data.enums.TagType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;

import java.util.List;

import static com.denimgroup.threadfix.util.ValidationUtils.HTML_ERROR;
import static com.denimgroup.threadfix.util.ValidationUtils.containsHTML;

@Service
@Transactional(readOnly = false) // used to be true
public class TagServiceImpl implements TagService {

    private static final SanitizedLogger LOG = new SanitizedLogger("TagService");

    @Autowired
    private TagDao tagDao;
    @Autowired
    private VulnerabilityCommentDao vulnerabilityCommentDao;

    @Override
    public List<Tag> loadAll() {
        return tagDao.retrieveAllActive();
    }

    @Override
    public Tag loadApplicationTag(String name) {
        return tagDao.retrieveAppTagByName(name);
    }

    @Override
    public Tag loadCommentTag(String name) {
        return tagDao.retrieveCommentTagByName(name);
    }

    @Override
    public List<Tag> loadTagsByName(String name) {
        return tagDao.retrieveTagsByName(name);
    }

    @Override
    @Transactional(readOnly = true)
    public Tag loadTag(int tagId) {
        return tagDao.retrieveById(tagId);
    }

    @Override
    @Transactional(readOnly = false)
    public void storeTag(Tag tag) {
        tagDao.saveOrUpdate(tag);
    }

    @Override
    @Transactional(readOnly = false)
    public void deleteById(int tagId) {
        LOG.info("Deleting Tag with ID " + tagId);
        Tag tag = loadTag(tagId);
        tag.setActive(false);
        tagDao.saveOrUpdate(tag);
    }

    @Override
    public void copyAppTagsToCommentTags() {
        List<Tag> appTags = loadAllApplicationTags();
        if (appTags == null) {
            LOG.info("There is no tags in system.");
            return;
        }
        LOG.info("About to copy " + appTags.size() + " application tags to comment tags.");
        for (Tag appTag : appTags) {
            if (loadCommentTag(appTag.getName()) == null) {
                LOG.info("Copying " + appTag.getName());
                Tag newCommentTag = new Tag();
                newCommentTag.setName(appTag.getName());
                newCommentTag.setEnterpriseTag(appTag.getEnterpriseTag());
                newCommentTag.setDefaultJsonFilter(appTag.getDefaultJsonFilter());
                newCommentTag.setType(TagType.COMMENT);
                tagDao.saveOrUpdate(newCommentTag);
            }
            appTag.setType(TagType.APPLICATION);
            tagDao.saveOrUpdate(appTag);
        }

    }

    @Override
    public void changeTagInVulnComments() {
        LOG.info("About to update all tags in Vulnerability Comments from Application Tag to Comment Tag.");
        List<VulnerabilityComment> vulnerabilityComments = vulnerabilityCommentDao.retrieveAllActive();
        if (vulnerabilityComments == null) {
            LOG.info("There is no vulnerability comments in the system.");
            return;
        }
        LOG.info("Looking for tags in " + vulnerabilityComments.size() + " vulnerability comments, and change them if found.");
        for (VulnerabilityComment comment: vulnerabilityComments) {
            List<Tag> newTags = CollectionUtils.list();
            for (Tag tag: comment.getTags()) {
                if (tag.getType() == TagType.APPLICATION) {
                    Tag sameTagInComment = loadCommentTag(tag.getName());
                    if (sameTagInComment != null)
                        newTags.add(sameTagInComment);
                    else
                        LOG.warn("Can't find comment tag " + tag.getName() + " to change for comment in vulnerability ID " + comment.getVulnerability().getId());
                } else
                    newTags.add(tag);
            }
            comment.setTags(newTags);
            vulnerabilityCommentDao.saveOrUpdate(comment);
        }


    }

    @Override
    public List<Tag> loadAllApplicationTags() {
        return tagDao.retrieveAllApplicationTags();
    }

    @Override
    public List<Tag> loadAllCommentTags() {
        return tagDao.retrieveAllCommentTags();
    }

    @Override
    public void updateTagTypes() {
        LOG.info("About to update type for all tags.");
        for (Tag tag: tagDao.retrieveAll()) {
            if (!tag.getTagForComment()) { // this is an application tag
                tag.setType(TagType.APPLICATION);
            } else {
                tag.setType(TagType.COMMENT);
            }
            tagDao.saveOrUpdate(tag);
        }
    }

    @Override
    public List<Tag> loadAllVulnTags() {
        return tagDao.retrieveAllVulnerabilityTags();
    }

    @Override
    public Tag loadTagWithType(String name, TagType type) {
        return tagDao.retrieveTagWithType(name, type);
    }

    @Override
    public void validate(Tag tag, BindingResult result) {
        Tag databaseTag;
        if (tag.getName().trim().equals("")) {
            result.rejectValue("name", null, null, "This field cannot be blank");
        }

        if (containsHTML(tag.getName())) {
            LOG.error(HTML_ERROR);
            result.rejectValue("name", null, null, HTML_ERROR);
        }

        if (tag.getType() == null) {
            result.rejectValue("type", null, null, "This field cannot be blank");
        } else { // Checking if type is valid
            TagType type = TagType.getTagType(tag.getType().toString());
            databaseTag = loadTagWithType(tag.getName().trim(), type);
            if (databaseTag != null && (tag.getId() == null || !databaseTag.getId().equals(tag.getId()))) {
                result.rejectValue("name", MessageConstants.ERROR_NAMETAKEN);
            }

            // Check if updating tag is enterprise tag
            if (tag.getId() != null) {
                databaseTag = loadTag(tag.getId());
                if (databaseTag == null || (databaseTag.getEnterpriseTag() != null && databaseTag.getEnterpriseTag())) {
                    result.rejectValue("name", MessageConstants.ERROR_INVALID, new String[]{"Tag Id"}, null);
                }
            }
        }
    }

    @Override
    public boolean isValidTags(List<Tag> allTags, List<Tag> tags) {
        for (Tag tag: tags) {
            if (!containTag(allTags, tag)) {
                LOG.warn("Tag ID " + tag.getId() + " is invalid.");
                return false;
            }
        }

        return true;
    }

    @Override
    public boolean containTag(List<Tag> allTags, Tag tag) {
        for (Tag tagInCol: allTags) {
            if (tagInCol.getId().compareTo(tag.getId()) == 0)
                return true;
        }
        return false;
    }
}