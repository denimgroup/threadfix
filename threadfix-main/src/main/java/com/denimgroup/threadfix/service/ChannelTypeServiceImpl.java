////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ScannerType;

@Service
@Transactional(readOnly = true)
public class ChannelTypeServiceImpl implements ChannelTypeService {

	private ChannelTypeDao channelTypeDao = null;
	
	protected final SanitizedLogger log = new SanitizedLogger(ChannelTypeService.class);

	@Autowired
	public ChannelTypeServiceImpl(ChannelTypeDao channelTypeDao) {
		this.channelTypeDao = channelTypeDao;
	}

	@Override
	public List<ChannelType> loadAll() {
		return channelTypeDao.retrieveAll();
	}

	@Override
	public ChannelType loadChannel(int channelId) {
		return channelTypeDao.retrieveById(channelId);
	}

	@Override
	public ChannelType loadChannel(String name) {
		return channelTypeDao.retrieveByName(name);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeChannel(ChannelType channelType) {
		channelTypeDao.saveOrUpdate(channelType);
	}
	
	@Override
	public List<ChannelType> getChannelTypeOptions(Application application) {
		List<ChannelType> channelTypeList = channelTypeDao.retrieveAll(), editedList = new ArrayList<>();
		if (channelTypeList == null)
			return null;
		
		Set<String> doNotIncludeList = new HashSet<>();
		doNotIncludeList.add(ScannerType.SENTINEL.getFullName());
		doNotIncludeList.add(ScannerType.VERACODE.getFullName());
		doNotIncludeList.add(ScannerType.QUALYSGUARD_WAS.getFullName());
		doNotIncludeList.add(ScannerType.MANUAL.getFullName());
		
		if (application != null && application.getChannelList() != null && 
				application.getChannelList().size() != 0) {
			for (ApplicationChannel applicationChannel : application.getChannelList()){
				if (applicationChannel != null && applicationChannel.getChannelType() != null)
					doNotIncludeList.add(applicationChannel.getChannelType().getName());
			}
		}
		
		for (ChannelType channelType : channelTypeList) {
			if (channelType != null && channelType.getName() != null && 
					!doNotIncludeList.contains(channelType.getName())) {
				editedList.add(channelType);
			}
		}
		
		if (editedList.size() == 0) {
			log.error("No suitable Channel Types were found for this Application, have you loaded the database?");
		}

		return editedList;
	}

}