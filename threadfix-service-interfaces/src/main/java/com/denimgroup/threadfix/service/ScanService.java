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
package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.Scan;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

/**
 * @author bbeverly
 * 
 */
public interface ScanService {

	/**
	 * @return
	 */
	List<Scan> loadAll();
	
	/**
	 * @param scanId
	 * @return
	 */
	Scan loadScan(Integer scanId);

	/**
	 * @param scan
	 */
	void storeScan(Scan scan);

	/**
	 * @param scan
	 */
	String downloadScan(Scan scan, String fullFilePath, HttpServletResponse response, String originalFileName);
	
	/**
	 * This method delegates the checking to the appropriate importer and returns the code
	 * that the importer returns.
	 * @param channelId
	 * @param fileName
	 * @return
	 */
    @Nonnull
	ScanCheckResultBean checkFile(Integer channelId, String fileName);

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
	long getUnmappedFindingCount(Integer scanId);

	/**
	 * Set the number of skipped results, the number without channel vulns, 
	 * and the number without generic vulns. We may want to just save these in the database at some point.
	 * @param scan
	 */
	void loadStatistics(Scan scan);

	/**
	 * @param number
	 */
	List<Scan> loadMostRecentFiltered(int number);
	
	/**
	 */
	int getScanCount();
	
	/**
	 */
	List<Scan> getTableScans(Integer page);

    /**
     *
     */
    void
	deleteScanFileLocations();

}
