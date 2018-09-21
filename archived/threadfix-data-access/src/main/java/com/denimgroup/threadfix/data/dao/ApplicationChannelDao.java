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
package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;

import java.util.Calendar;

/**
 * Basic DAO class for the Channel entity.
 * 
 * @author mcollins
 */

public interface ApplicationChannelDao extends GenericObjectDao<ApplicationChannel> {

	/**
	 * @param appId
	 * @param channelId
	 * @return
	 */
	ApplicationChannel retrieveByAppIdAndChannelId(Integer appId, Integer channelId);
	
	/**
	 *
	 * @param channelId ID of the ApplicationChannel object
	 * @return the time the last scan was uploaded to this channel
	 */
	Calendar getMostRecentQueueScanTime(Integer channelId);

	/**
	 *
	 * @param channelId ID of the ApplicationChannel object
	 * @return the time the last scan was uploaded to this channel
	 */
	Calendar getMostRecentScanTime(Integer channelId);


}
