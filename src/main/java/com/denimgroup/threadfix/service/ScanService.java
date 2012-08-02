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
package com.denimgroup.threadfix.service;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.Scan;

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
	 * Save a scan file and add a request to the queue with the appropriate
	 * filename and ApplicationChannel id.
	 * 
	 * @param channelId
	 * @param fileName
	 * @param queueSender
	 */
	void addFileToQueue(Integer channelId, String fileName);
	
	/**
	 * This method delegates the checking to the appropriate importer and returns the code
	 * that the importer returns.
	 * @param channelId
	 * @param fileName
	 * @return
	 */
	String checkFile(Integer channelId, String fileName);
	
	/**
	 * 
	 * @param channelId
	 * @param file
	 * @return
	 */
	Integer saveEmptyScanAndGetId(Integer channelId, String fileName);

	/**
	 * 
	 * @param emptyScanId
	 */
	void addEmptyScanToQueue(Integer emptyScanId);
	
	/**
	 * 
	 * @param emptyScanId
	 */
	void deleteEmptyScan(Integer emptyScanId);

	/**
	 * 
	 * @param channelId
	 * @param file
	 * @return
	 */
	String saveFile(Integer channelId, MultipartFile file);

	/**
	 * 
	 * @param scanId
	 * @return
	 */
	long getFindingCount(Integer scanId);

}
