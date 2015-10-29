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
import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.GenericSeverityDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.SeverityMap;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.service.queue.QueueSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
@Transactional(readOnly = false) // used to be true
public class ChannelSeverityServiceImpl implements ChannelSeverityService {

	@Autowired
	private ChannelSeverityDao channelSeverityDao;
	@Autowired
	private ChannelTypeDao channelTypeDao;
	@Autowired
	private GenericSeverityDao genericSeverityDao;

	@Override
	public List<ChannelSeverity> loadByChannel(String channelTypeName) {
		return channelSeverityDao.retrieveByChannel(
				channelTypeDao.retrieveByName(channelTypeName));
	}

	@Override
	public ChannelSeverity loadById(int id) {
		return channelSeverityDao.retrieveById(id);
	}

	@Override
	public List<Object> loadAllByChannel() {

		List<Object> list = CollectionUtils.list();
		for (ChannelType channelType : channelTypeDao.retrieveAll()) {
			Map<String, Object> map = CollectionUtils.map();
			map.put("channelType", channelType);
			map.put("channelSeverities", channelSeverityDao.retrieveByChannel(channelType));
			list.add(map);
		}

		return list;
	}

	@Override
	@Transactional(readOnly=false)
	public String updateChannelSeverityMappings(List<ChannelSeverity> channelSeverities) {

		String ids = "";
		for (ChannelSeverity channelSeverity : channelSeverities) {
			GenericSeverity genericSeverity = genericSeverityDao.retrieveById(channelSeverity.getSeverityMap().getGenericSeverity().getId());
			if (genericSeverity != null) {
				ChannelSeverity dbChannelSeverity = channelSeverityDao.retrieveById(channelSeverity.getId());

				if (dbChannelSeverity.getSeverityMap() != null)
					dbChannelSeverity.getSeverityMap().setGenericSeverity(genericSeverity);
				else {
					SeverityMap map = new SeverityMap();
					map.setChannelSeverity(dbChannelSeverity);
					map.setGenericSeverity(genericSeverity);
					dbChannelSeverity.setSeverityMap(map);
				}
				channelSeverityDao.saveOrUpdate(dbChannelSeverity);
				ids = ids + dbChannelSeverity.getId() + ",";
			}
		}
		return ids;
	}

	@Override
	public void updateExistingVulns(String channelSeverityIds) {
		assert channelSeverityIds != null;
		List<Integer> idsList = CollectionUtils.list();
		String[] ids = channelSeverityIds.split(",");
		for (String idStr : ids) {
			Integer channelSeverityId = IntegerUtils.getIntegerOrNull(idStr);
			if (channelSeverityId != null) {
				idsList.add(channelSeverityId);
			}
		}

		if (idsList.size() > 0) {
			channelSeverityDao.updateExistingVulns(idsList);
		}
	}
}
