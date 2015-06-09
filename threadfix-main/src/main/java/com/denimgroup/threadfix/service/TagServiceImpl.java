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
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = false) // used to be true
public class TagServiceImpl implements TagService {

    private final SanitizedLogger log = new SanitizedLogger("TagService");

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
        log.info("Deleting Tag with ID " + tagId);
        Tag tag = loadTag(tagId);
        tag.setActive(false);
        tagDao.saveOrUpdate(tag);
    }

    @Override
    public void copyAppTagsToCommentTags() {
        List<Tag> appTags = loadAllApplicationTags();
        if (appTags == null) {
            log.info("There is no tags in system.");
            return;
        }
        log.info("About to copy " + appTags.size() + " application tags to comment tags.");
        for (Tag appTag : appTags) {
            if (loadCommentTag(appTag.getName()) == null) {
                log.info("Copying " + appTag.getName());
                Tag newCommentTag = new Tag();
                newCommentTag.setName(appTag.getName());
                newCommentTag.setEnterpriseTag(appTag.getEnterpriseTag());
                newCommentTag.setDefaultJsonFilter(appTag.getDefaultJsonFilter());
                newCommentTag.setTagForComment(true);
                tagDao.saveOrUpdate(newCommentTag);
            }
        }

    }

    @Override
    public void changeTagInVulnComments() {
        log.info("About to update all tags in Vulnerability Comments from Application Tag to Comment Tag.");
        List<VulnerabilityComment> vulnerabilityComments = vulnerabilityCommentDao.retrieveAllActive();
        if (vulnerabilityComments == null) {
            log.info("There is no vulnerability comments in the system.");
            return;
        }
        log.info("Looking for tags in " + vulnerabilityComments.size() + " vulnerability comments, and change them if found.");
        for (VulnerabilityComment comment: vulnerabilityComments) {
            List<Tag> newTags = CollectionUtils.list();
            for (Tag tag: comment.getTags()) {
                if (tag.getTagForComment() == null || !tag.getTagForComment()) {
                    Tag sameTagInComment = loadCommentTag(tag.getName());
                    if (sameTagInComment != null)
                        newTags.add(sameTagInComment);
                    else
                        log.warn("Can't find comment tag " + tag.getName() + " to change for comment in vulnerability ID " + comment.getVulnerability().getId());
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
}