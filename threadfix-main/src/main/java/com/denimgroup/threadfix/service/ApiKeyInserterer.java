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

import com.denimgroup.threadfix.data.dao.APIKeyDao;
import com.denimgroup.threadfix.data.entities.APIKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import java.util.List;

@Component
public class ApiKeyInserterer extends SpringBeanAutowiringSupport implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private APIKeyDao apiKeyDao;

    @Transactional(readOnly = false)
    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        List<APIKey> apiKeys = apiKeyDao.retrieveAll();

        if (apiKeys.isEmpty()) {
            APIKey key = new APIKey();
            key.setApiKey("viwfFyFURJYPzdmH4fycQOvg4lBchgRvzfJSAEBg");
            apiKeyDao.saveOrUpdate(key);
        }
    }
}
