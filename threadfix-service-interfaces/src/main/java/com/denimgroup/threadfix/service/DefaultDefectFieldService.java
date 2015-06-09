package com.denimgroup.threadfix.service;

import java.util.List;
import com.denimgroup.threadfix.data.entities.DefaultDefectField;
import com.denimgroup.threadfix.data.entities.Vulnerability;

public interface DefaultDefectFieldService {

	public String getDefaultValueForVulns(DefaultDefectField defaultDefectField, List<Vulnerability> vulnerabilities);

	/**
	 * Should parse Json results to update/create defaults, but also validate the defaults (tag existence...)
	 * @param newDefaults
	 */
	public List<DefaultDefectField> parseDefaultDefectsFields(String newDefaultsJson);
}
