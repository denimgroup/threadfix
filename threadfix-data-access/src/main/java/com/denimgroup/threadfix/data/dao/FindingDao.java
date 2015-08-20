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

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;

import java.util.List;

/**
 * Basic DAO class for the Finding entity.
 * 
 * @author dwolf
 */
public interface FindingDao extends GenericObjectDao<Finding> {

	/**
	 * Find a list of possible sourceFileLocations
	 * 
	 * @param hint
	 * @return
	 */
	List<String> retrieveByHint(String hint, Integer appId);
	
	/**
	 * A list of the most recent Dynamic Findings matching the application and User
	 * 
	 * @param appId
	 * @param userId
	 * @return
	 */
	List<Finding> retrieveLatestDynamicByAppAndUser(int appId, int userId);
	
	/**
	 * The most recent Static Findings matching the application and User
	 * 
	 * @param appId
	 * @param userId
	 * @return
	 */
	List<Finding> retrieveLatestStaticByAppAndUser(int appId, int userId);

	/**
	 * @param finding
	 */
	void delete(Finding finding);

	/**
	 * 
	 * @param scanId
	 * @param page
	 * @return
	 */
	List<Finding> retrieveFindingsByScanIdAndPage(Integer scanId, int page);

	/**
	 * 
	 * @param scanId
	 * @param page
	 * @return
	 */
	Object retrieveUnmappedFindingsByScanIdAndPage(Integer scanId, int page);

	List<String> retrieveManualUrls(Integer appId);

    List<Finding> retrieveUnmappedFindingsByPage(int page, Integer appId);

	List<Finding> retrieveByChannelVulnerabilityAndApplication(Integer channelVulnerabilityId, Integer applicationId);

	long getTotalUnmappedFindings();

    List<Finding> retrieveByGenericSeverityAndChannelType(GenericSeverity genericSeverity, ChannelType channelType);

    List<Finding> getUnmappedFindings();
}
