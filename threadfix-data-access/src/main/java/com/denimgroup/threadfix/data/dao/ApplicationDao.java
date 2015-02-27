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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Vulnerability;

import java.util.List;
import java.util.Set;

/**
 * Basic DAO class for the Application entity.
 * 
 * @author bbeverly
 */
public interface ApplicationDao extends GenericObjectDao<Application> {

    /**
     *
     * @param name
     * @param teamId
     * @return
     */
    public Application retrieveByName(String name, int teamId);

    /**
	 *
     * @param uniqueId
     * @param teamId
     * @return
     */
    public Application retrieveByUniqueId(String uniqueId, int teamId);

    /**
	 * 
	 * @param authenticatedTeamIds
	 * @return
	 */
	List<Application> retrieveAllActiveFilter(Set<Integer> authenticatedTeamIds);

	/**
	 * 
	 * @param application
	 * @return
	 */
	List<Integer> loadVulnerabilityReport(Application application);

	/**
	 * 
	 * @param appIds
	 * @return
	 */
	List<String> getTeamNames(List<Integer> appIds);
	
	/**
	 * 
	 * @param app
	 */
	List<Vulnerability> getVulns(Application app);
	
	/**
	 */
	List<Integer> getTopXVulnerableAppsFromList(int numApps, List<Integer> teamIdList , List<Integer> applicationIdList);

    long getUnmappedFindingCount(Integer appId);

    List<Application> getTopAppsFromList(List<Integer> applicationIdList);

    List<Object[]> getPointInTime(List<Integer> applicationIdList);

	long getApplicationCount();
}
