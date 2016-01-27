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

import com.denimgroup.threadfix.data.dao.ApplicationCriticalityDao;
import com.denimgroup.threadfix.data.entities.ApplicationCriticality;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = false) // used to be true
public class ApplicationCriticalityServiceImpl implements ApplicationCriticalityService {

	private ApplicationCriticalityDao applicationCriticalityDao;
	
	@Autowired
	public ApplicationCriticalityServiceImpl(ApplicationCriticalityDao applicationCriticalityDao) {
		this.applicationCriticalityDao = applicationCriticalityDao;
	}
	
	@Override
	public List<ApplicationCriticality> loadAll() {
		return applicationCriticalityDao.retrieveAll();
	}

	@Override
	public ApplicationCriticality loadApplicationCriticality(
			int applicationCriticalityId) {
		return applicationCriticalityDao.retrieveById(applicationCriticalityId);
	}

	@Override
	public ApplicationCriticality loadApplicationCriticality(
			String applicationCriticalityName) {
		return applicationCriticalityDao.retrieveByName(applicationCriticalityName);
	}

}
