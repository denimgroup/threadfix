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

import com.denimgroup.threadfix.data.entities.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Basic DAO class for the Scan entity.
 * TODO break this down, there's a lot going on in this class
 * 
 * @author mcollins
 */
public interface ScanDao extends GenericObjectDao<Scan> {
	
	/**
	 * This method returns a map of severities -> counts for vulnerabilities for
	 * mapped repeat findings in the scan.
	 *
	 * @param scan
	 * @return
	 */
	Map<String, Object> getMapSeverityMap(Scan scan);
	
	/**
	 * This method returns a map of severities -> counts for vulnerabilities
	 * for findings in the scan.
	 *
	 * @param scan
	 * @return
	 */
	Map<String,Object> getFindingSeverityMap(Scan scan);

	/**
	 * 
	 * @param applicationIdList
	 * @return
	 */
	List<Scan> retrieveByApplicationIdList(List<Integer> applicationIdList);

	/**
	 * 
	 * @param scan
	 */
	void delete(Scan scan);
	
	/**
	 * Delete a close map. These are saved by cascade but not always deleted that way.
	 * @param scan
	 */
	void deleteMap(ScanCloseVulnerabilityMap map);
	
	/**
	 * Delete a reopen map. These are saved by cascade but not always deleted that way.
	 * @param scan
	 */
	void deleteMap(ScanReopenVulnerabilityMap map);
	
	/**
	 * Delete a duplicate map. These are saved by cascade but not always deleted that way.
	 * @param scan
	 */
	void deleteMap(ScanRepeatFindingMap map);

	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getFindingCount(Integer scanId);

	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getFindingCountUnmapped(Integer scanId);
	
	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getTotalNumberSkippedResults(Integer scanId);
	
	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getNumberWithoutChannelVulns(Integer scanId);
	
	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getNumberWithoutGenericMappings(Integer scanId);

	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getTotalNumberFindingsMergedInScan(Integer scanId);

	/**
	 * 
	 * @param scan
	 */
	void deleteFindingsAndScan(Scan scan);

	/**
	 * @param number 
	 */
	List<Scan> retrieveMostRecent(int number);
	
	/**
	 * @param number 
	 */
	List<Scan> retrieveMostRecent(int number, Set<Integer> authenticatedAppIds, 
			Set<Integer> authenticatedTeamIds);
	
	/**
	 *
	 */
	int getScanCount();

	/**
	 * 
	 */
	int getScanCount(Set<Integer> authenticatedAppIds, Set<Integer> authenticatedTeamIds);

	/**
	 *
	 */
	List<Scan> getTableScans(Integer page);
	
	/**
	 *
	 */
	List<Scan> getTableScans(Integer page, Set<Integer> authenticatedAppIds, Set<Integer> authenticatedTeamIds);
	
	/**
	 * 
	 */
	Map<String, Object> getCountsForScans(List<Integer> ids);

    /**
     *
     */
    int deleteScanFileLocations();


    /**
     *
     * @return List<Scan>
     */
    List<String> loadScanFilenames();

	Long totalFindingsThatNeedCounters();

	List<Finding> getFindingsThatNeedCounters(int page);

	List<ScanRepeatFindingMap> getMapsThatNeedCounters(int current);

	Long totalMapsThatNeedCounters();

}

