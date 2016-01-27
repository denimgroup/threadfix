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

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.denimgroup.threadfix.data.entities.SecurityEvent;

/**
 * @author bbeverly
 * 
 */
public interface LogParserService {

	/**
	 * Set a file so that the LogParserService knows which file to parse.
	 * 
	 * @param file
	 */
	void setFile(MultipartFile file);

	/**
	 * Parse the file with an appropriate parser for the type of log
	 * and return a list of SecurityEvents that have already been matched
	 * to rules.
	 * 
	 * @return
	 */
	List<SecurityEvent> parseInput();

	/**
	 * Give the LogParserService the name of a file to open and parse.
	 * 
	 * @param string
	 */
	void setFileAsString(String string);

	/**
	 * This is important so that the service can pick what kind of LogParser to use.
	 * 
	 * @param wafId
	 */
	void setWafId(Integer wafId);
}
