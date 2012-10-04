////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.data.dao;

import java.util.Calendar;
import java.util.List;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;

/**
 * Basic DAO class for the Channel entity.
 * 
 * @author mcollins
 */

public interface ApplicationChannelDao {

	/**
	 * @return
	 */
	List<ApplicationChannel> retrieveAll();

	/**
	 * @param appId
	 * @param channelId
	 * @return
	 */
	ApplicationChannel retrieveByAppIdAndChannelId(Integer appId, Integer channelId);

	/**
	 * @param id
	 * @return
	 */
	ApplicationChannel retrieveById(int id);

	/**
	 * @param applicationChannel
	 */
	void saveOrUpdate(ApplicationChannel applicationChannel);
	
	/**
	 * 
	 * @param id
	 * @return
	 */
	Calendar getMostRecentQueueScanTime(Integer channelId);

}
