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
package com.denimgroup.threadfix.importer.interop;

import com.denimgroup.threadfix.data.ScanCheckResultBean;
import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.InputStream;
import java.util.Calendar;

/**
 * 
 * 
 * @author bbeverly
 * @author mcollins
 * 
 */
public interface ChannelImporter {

	/**
	 * Returns the parsed results of a scan.
	 * 
	 * @return
	 */
	@Transactional
    @Nullable
	Scan parseInput();

	/**
	 * Before files go on the queue, they need to be checked to make sure they are valid.
	 * 
	 * @return a bean with status and date fields. The success code is the SUCCESSFUL_SCAN field 
	 * in the ChannelImporter interface. Other return codes are also given in
	 * the interface and are all simply echoed to the user as an error.
	 */
    @Nonnull
	ScanCheckResultBean checkFile();

	/**
	 * @param applicationChannel
	 */
	void setChannel(ApplicationChannel applicationChannel);
	
	/**
	 * Set the input stream directly
	 * @param inputStream
	 */
	void setInputStream(InputStream inputStream);

	/**
	 * Sets the filename containing the scan results.
	 * 
	 * @param fileName
	 *            The file containing the scan results.
	 */
	void setFileName(String fileName);

	/**
	 * Sets the original filename of the uploaded scan.
	 *
	 * @param originalFileName
	 */
    void setOriginalFileName(String originalFileName);
	
	/**
	 * Delete the scan file from disk, if it has been saved there.
	 */
	void deleteScanFile();
	
	/**
	 * 
	 * @return
	 */
	Calendar getTestDate();

}
