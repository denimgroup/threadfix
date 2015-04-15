package com.denimgroup.threadfix.service;

import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;
import com.denimgroup.threadfix.data.entities.Vulnerability;

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

}
