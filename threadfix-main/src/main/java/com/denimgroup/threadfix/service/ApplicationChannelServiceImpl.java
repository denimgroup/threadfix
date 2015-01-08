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

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ApplicationChannelDao;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;

@Service
@Transactional(readOnly = false) // used to be true
public class ApplicationChannelServiceImpl implements ApplicationChannelService {
	
	private ApplicationChannelDao applicationChannelDao = null;

	@Autowired
	public ApplicationChannelServiceImpl(ApplicationChannelDao applicationChannelDao) {
		this.applicationChannelDao = applicationChannelDao;
	}

	@Override
	public List<ApplicationChannel> loadAll() {
		return applicationChannelDao.retrieveAll();
	}

	@Override
	public ApplicationChannel loadApplicationChannel(int applicationChannelId) {
		return applicationChannelDao.retrieveById(applicationChannelId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeApplicationChannel(ApplicationChannel applicationChannel) {
		applicationChannelDao.saveOrUpdate(applicationChannel);
	}

	@Override
	public ApplicationChannel retrieveByAppIdAndChannelId(int appId, int id) {
		return applicationChannelDao.retrieveByAppIdAndChannelId(appId, id);
	}

}
