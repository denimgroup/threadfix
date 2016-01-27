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

import com.denimgroup.threadfix.data.dao.EmailListDao;
import com.denimgroup.threadfix.data.dao.GenericNamedObjectDao;
import com.denimgroup.threadfix.data.entities.EmailList;
import com.denimgroup.threadfix.data.entities.ScheduledEmailReport;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * @author zabdisubhan
 */

@Service
@Transactional(readOnly = false)
public class EmailListServiceImpl extends AbstractNamedObjectService<EmailList> implements EmailListService {

    protected final SanitizedLogger log = new SanitizedLogger(EmailListServiceImpl.class);

    @Autowired
    private EmailListDao emailListDao;

    @Override
    public GenericNamedObjectDao<EmailList> getDao() {
        return emailListDao;
    }

    @Override
    public String removeEmailAddress(EmailList emailList, String emailAddress) {

        List<String> emailAddresses = emailList.getEmailAddresses();

        emailAddresses.remove(emailAddress);

        saveOrUpdate(emailList);

        return emailAddress;
    }

    @Override
    public String addEmailAddress(EmailList emailList, String emailAddress) {

        List<String> emailAddresses = emailList.getEmailAddresses();

        emailAddresses.add(emailAddress);

        saveOrUpdate(emailList);

        return emailAddress;
    }

    @Override
    public void delete(EmailList emailList) {

        List<ScheduledEmailReport> scheduledEmailReports = emailList.getScheduledEmailReports();

        for (ScheduledEmailReport ser : scheduledEmailReports) {
            ser.getEmailLists().remove(emailList);
        }

        markInactive(emailList);
        emailList.setName("del-" + emailList.getId() + "_" + emailList.getName());
        saveOrUpdate(emailList);
    }

    @Override
    public boolean nameExists(String name) {
        EmailList emailList = loadByName(name);
        return (emailList != null && emailList.isActive());
    }
}
