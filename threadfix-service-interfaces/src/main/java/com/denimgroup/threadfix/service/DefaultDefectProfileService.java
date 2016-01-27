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
import java.util.Map;

import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import org.springframework.validation.BindingResult;

public interface DefaultDefectProfileService {

	public DefaultDefectProfile loadDefaultProfile(Integer defaultProfileId);

	public void storeDefaultDefectProfile(DefaultDefectProfile defaultDefectProfile);

	/**
	 * This function retrieves all the default values for a corresponding default profile and list of vulns 
	 * and returns a map containing the field names and their default value associated if this value exists
	 * @param defectTracker
	 * @param vulnerabilities
	 */
	public Map<String,Object> getAllDefaultValuesForVulns(DefaultDefectProfile defaultDefectProfile, List<Vulnerability> vulnerabilities);

	public void removeDefaultFields(DefaultDefectProfile defaultDefectProfile);

	/**
	 * This function should update the fields with those provided, 
	 * but should also delete the fields that were not provided
	 * @param defectTracker
	 * @param newDefaults
	 */
	public void updateDefaultFields(DefaultDefectProfile defaultDefectProfile, List<DefaultDefectField> newDefaults);

	public void deleteProfileById(Integer defaultProfileId);

	public DefaultDefectProfile loadAppDefectProfileByName(String name, Integer defectTrackerId, Integer appId);

	/**
	 * This function checks if name of default defect profile is duplicate.
	 * @param defaultDefectProfile
	 * @param result
	 */
	void validateName(DefaultDefectProfile defaultDefectProfile, BindingResult result);
}
