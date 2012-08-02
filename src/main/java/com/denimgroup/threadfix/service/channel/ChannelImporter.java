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
package com.denimgroup.threadfix.service.channel;

import java.io.InputStream;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * 
 * 
 * @author bbeverly
 * @author mcollins
 * 
 */
public interface ChannelImporter {

	public static final String SUCCESSFUL_SCAN = "Valid Scan file.";
	public static final String OLD_SCAN_ERROR = "A newer scan has been uploaded in this channel.";
	public static final String EMPTY_SCAN_ERROR = "Scan file is empty.";
	public static final String DUPLICATE_ERROR = "Scan file has already been uploaded.";
	public static final String WRONG_FORMAT_ERROR = "Scan file is in the wrong format.";
	public static final String NULL_INPUT_ERROR = "The scan could not be completed because there was null input";
	public static final String OTHER_ERROR = "The scan file encountered an unknown error.";
	public static final String BADLY_FORMED_XML = "The XML was not well-formed and could not be parsed.";
	
	/**
	 * Returns the parsed results of a scan.
	 * 
	 * @return
	 */
	Scan parseInput();
	
	/**
	 * Before files go on the queue, they need to be checked to make sure they are valid.
	 * 
	 * @return a status string. The success code is the SUCCESSFUL_SCAN field 
	 * in the ChannelImporter interface. Other return codes are also given in
	 * the interface and are all simply echoed to the user as an error.
	 */
	String checkFile();

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
	 * Delete the scan file from disk, if it has been saved there.
	 */
	void deleteScanFile();

}
