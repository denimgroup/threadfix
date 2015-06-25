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

import com.denimgroup.threadfix.data.dao.EmailListDao;
import com.denimgroup.threadfix.data.entities.EmailList;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author zabdisubhan
 */

@Service
@Transactional(readOnly = false)
public class EmailListServiceImpl implements EmailListService {

    protected final SanitizedLogger log = new SanitizedLogger(EmailListServiceImpl.class);

    @Autowired
    private EmailListDao emailListDao;

    @Override
    public List<EmailList> loadAll() {
        return emailListDao.retrieveAll();
    }

    @Override
    public List<EmailList> loadAllActive() {
        return emailListDao.retrieveAllActive();
    }

    @Override
    public EmailList loadById(int emailListId) {
        return emailListDao.retrieveById(emailListId);
    }

    @Override
    public EmailList loadByName(String emailListName) {
        return emailListDao.retrieveByName(emailListName);
    }

    @Override
    public void store(EmailList emailList) {
        emailListDao.saveOrUpdate(emailList);
    }

    @Override
    public void deleteById(int emailListId) {
        EmailList emailList = loadById(emailListId);
        log.info("Deleting EmailList with ID: " + emailListId + " and Name: " + emailList.getName());
        emailList.setActive(false);
        emailListDao.saveOrUpdate(emailList);
    }

    @Override
    public String removeEmailAddress(EmailList emailList, String emailAddress) {

        List<String> emailAddresses = emailList.getEmailAddresses();

        emailAddresses.remove(emailAddress);

        store(emailList);

        return emailAddress;
    }

    @Override
    public String addEmailAddress(EmailList emailList, String emailAddress) {

        List<String> emailAddresses = emailList.getEmailAddresses();

        emailAddresses.add(emailAddress);

        store(emailList);

        return emailAddress;
    }
}
