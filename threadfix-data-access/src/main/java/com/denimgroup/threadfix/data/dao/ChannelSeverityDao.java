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
package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;

import java.util.List;

/**
 * @author bbeverly
 * 
 */
public interface ChannelSeverityDao {

	/**
	 *Returns a ChannelSeverity list based on the channel
	 * @param channelType
	 * @return
	 */
	List<ChannelSeverity> retrieveByChannel(ChannelType channelType);
	
	/**
	 * Returns a single ChannelSeverity rating based on the channel and name.
	 * 
	 * @param channelType
	 *            The channel.
	 * @param code
	 *            The code identifying the severity to pull. Note that this is
	 *            not the same as the Name property, but is the value from the
	 *            channel's output file.
	 * @return
	 */
	ChannelSeverity retrieveByCode(ChannelType channelType, String code);
	
	/**
	 * @param channelSeverityId
	 * @return
	 */
	ChannelSeverity retrieveById(int channelSeverityId);

	/**
	 * Creates or updates a channel severity.
	 * 
	 * @param channelSeverity
	 *            The severity to save or update.
	 */
	void saveOrUpdate(ChannelSeverity channelSeverity);

	void insert(List<ChannelSeverity> channelSeverities);

	void updateExistingVulns(List<Integer> channelSeverityIds);
}
