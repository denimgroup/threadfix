////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.data.enums.TagType;
import org.springframework.validation.BindingResult;

import java.util.List;

/**
 * @author stran
 * 
 */
public interface TagService {
    List<Tag> loadAll();
    Tag loadApplicationTag(String name);
    Tag loadCommentTag(String name);
    List<Tag> loadTagsByName(String name);
    Tag loadTag(int tagId);
    void storeTag(Tag tag);
    void deleteById(int tagId);
    void copyAppTagsToCommentTags();
    void changeTagInVulnComments();
    List<Tag> loadAllApplicationTags();
    List<Tag> loadAllCommentTags();

    void updateTagTypes();

    List<Tag> loadAllVulnTags();

    Tag loadTagWithType(String name, TagType type);

    void validate(Tag tag, BindingResult result);

    boolean isValidTags(List<Tag> allTags, List<Tag> tags);

    boolean containTag(List<Tag> allTags, Tag tag);

    List<Tag> setEnterpriseTag(List<Tag> tags);
}
