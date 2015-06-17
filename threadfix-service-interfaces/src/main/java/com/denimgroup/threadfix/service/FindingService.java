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

import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import org.springframework.validation.BindingResult;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author bbeverly
 * 
 */
public interface FindingService {

	/**
	 * @return
	 */
	List<Finding> loadAll();

	/**
	 * @param findingId
	 * @return
	 */
	Finding loadFinding(int findingId);
	
	/**
	 * Load a list of suggested SourceFileNames from a String fragment and an Application id.
	 * 
	 * @param hint
	 * @return
	 */
	List<String> loadSuggested(String hint, int appId);
	
	/**
	 * Load a list of the most recent Static Findings matching the application and User
	 * 
	 * @param appId
	 * @param userId
	 * @return
	 */
	List<Finding> loadLatestStaticByAppAndUser(int appId, int userId);
	
	/**
	 * Load a list of the most recent Dynamic Findings matching the application and User
	 * 
	 * @param appId
	 * @param userId
	 * @return
	 */
	List<Finding> loadLatestDynamicByAppAndUser(int appId, int userId);

	/**
	 * @param finding
	 */
	void storeFinding(Finding finding);
	
	/**
	 * Parse a finding out of the parameters of an HTTP request. 
	 * Used for REST to cut down on Controller complexity.
	 * @param request
	 * @return
	 */
	Finding parseFindingFromRequest(HttpServletRequest request);
	
	/**
	 * Check the possible Finding params in a request.
	 * Used for REST to cut down on Controller complexity.
	 * @param request
	 * @return
	 */
    @Nonnull
	String checkRequestForFindingParameters(@Nonnull HttpServletRequest request);

	/**
	 * 
	 * @param scanId
	 * @param bean
	 * @return
	 */
	List<Finding> getFindingTable(Integer scanId, TableSortBean bean);

	/**
	 * 
	 * @param scanId
	 * @param bean
	 * @return
	 */
	Object getUnmappedFindingTable(Integer scanId, TableSortBean bean);

	/**
	 * This one is for the application page; it doesn't need scan ID because all scan IDs are included.
	 * @param bean sort bean, including the page number
	 * @return
	 */
	List<Finding> getUnmappedFindingTable(TableSortBean bean);

	/**
	 * 
	 * @param appId
	 * @return
	 */
	List<String> getRecentStaticVulnTypes(int appId);

	/**
	 * 
	 * @param appId
	 * @return
	 */
	List<String> getRecentDynamicVulnTypes(int appId);

	/**
	 * 
	 * @param appId
	 * @return
	 */
	List<String> getRecentStaticPaths(int appId);

	/**
	 * 
	 * @param appId
	 * @return
	 */
	List<String> getRecentDynamicPaths(int appId);

	/**
	 * 
	 * @return
	 */
	List<ChannelSeverity> getManualSeverities();

	/**
	 * 
	 * @param finding
	 * @param result
	 */
	void validateManualFinding(Finding finding, BindingResult result, boolean isStatic);

	List<String> getAllManualUrls(Integer appId);

	long getTotalUnmappedFindings();

    List<Finding> loadByGenericSeverityAndChannelType(GenericSeverity genericSeverity, ChannelType channelType);
}
