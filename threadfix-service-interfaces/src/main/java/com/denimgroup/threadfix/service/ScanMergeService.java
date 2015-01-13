////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * @author mcollins
 * 
 */
public interface ScanMergeService {
	
	/**
	 * Iterate through all the sourceFileLocations in the Findings of the Application
	 * and calculate a new path based on the current projectRoot. This is best used
	 * after calculating a new projectRoot, or it won't do anything.
	 * 
	 * @param application
	 */
	void updateSurfaceLocation(Application application);
	
	/**
	 * This method merges together Vulnerabilities that match. They could have missed being
	 * matched initially if they had different roots that were then parsed out.
	 * 
	 * @param application
	 */
	void updateVulnerabilities(Application application);

	/**
	 * This method does the actual scan processing work. It is usually called from QueueListener or
	 * one of the RPC methods.
	 * 
	 * @param channelId
	 * @param fileName
	 * @return
	 */
	boolean processScan(Integer channelId, String fileName, Integer statusId,
			String userName);
	
	/**
	 * This method allows skipping the queue by wrapping all the required functionality into
	 * one method.  A script might time out and cease to function unless it gets its results,
	 * which is why this bypass is available.
	 * 
	 * @param channelId
	 * @param fileName
	 * @return
	 */
	Scan saveRemoteScanAndRun(Integer channelId, String fileName);
	
	/**
	 * 
	 * @param scan
	 * @return
	 */
	Scan processRemoteScan(Scan scan);

}
