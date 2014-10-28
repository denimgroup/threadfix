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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGenerator;
import com.denimgroup.threadfix.service.waf.RealTimeProtectionGeneratorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Calendar;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

@Service
@Transactional(readOnly = false) // used to be true
public class TagServiceImpl implements TagService {

    private final SanitizedLogger log = new SanitizedLogger("TagService");

    @Autowired
    private TagDao tagDao;

    @Override
    public List<Tag> loadAll() {
        return tagDao.retrieveAllActive();
    }

    @Override
    public Tag loadTag(String name) {
        return tagDao.retrieveByName(name);
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
}