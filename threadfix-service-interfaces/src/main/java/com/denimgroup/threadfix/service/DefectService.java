////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * @author bbeverly
 * 
 */
public interface DefectService {

	/**
	 * @return
	 */
	List<Defect> loadAll();

	/**
	 * @param defectId
	 * @return
	 */
	Defect loadDefect(int defectId);

	/**
	 * @param nativeId
	 * @return
	 */
	Defect loadDefect(String nativeId);

	/**
	 * @param defect
	 */
	void storeDefect(Defect defect);

	/**
	 * Construct a new Defect based on the parameters and submit it to a tracker.
	 * @param vulns
	 * @param summary
	 * @param preamble
	 * @param component
	 * @param version
	 * @param severity
	 * @return
	 */
	Defect createDefect(List<Vulnerability> vulns, String summary, String preamble,
			String component, String version, String severity, String priority, String status);

	/**
	 * Get the error message associated with the submission of the list of Vulnerabilities.
	 * 
	 * @param vulns
	 * @return
	 */
	String getErrorMessage(List<Vulnerability> vulns);

	/**
	 * Update open status of each Vulnerability in the Application by checking the defect tracker.
	 * 
	 * @param application
	 */
	boolean updateVulnsFromDefectTracker(Integer applicationId);
	
	/**
	 * 
	 * @param defectTrackerId
	 */
	void deleteByDefectTrackerId(Integer defectTrackerId);
	
	/**
	 * 
	 * @param applicationId
	 */
	void deleteByApplicationId(Integer applicationId);
	
	/**
	 * 
	 * @param vulnerabilities
	 * @param id
	 * @return
	 */
	boolean mergeDefect(List<Vulnerability> vulnerabilities, String id);
	
}
