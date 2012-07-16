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
package com.denimgroup.threadfix.service.defects;

import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * An abstract class providing a base implementation of a defect tracker. This
 * class should be extended by platform specific trackers.
 * 
 * @author jraim
 * 
 */
public abstract class AbstractDefectTracker {
	
	protected final static String LOGIN_FAILURE = "Login Failure";
	protected final static String BAD_CONFIGURATION = "Your configuration is invalid: check your URL.";

	// Common log for all Defect Tracker Exporters.
	protected final Log log = LogFactory.getLog(this.getClass());

	/**
	 * @param vulnerabilities
	 * @param metadata
	 * @return
	 */
	public abstract String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata);

	/**
	 * 
	 * @param endpointURL
	 * @param bugID
	 * @return
	 */
	public abstract String getBugURL(String endpointURL, String bugID);
	
	/**
	 * 
	 */
	public abstract boolean hasValidUrl();
	
	/**
	 * @return
	 */
	public abstract String getProjectIdByName();

	/**
	 * @return
	 */
	public abstract String getTrackerError();

	/**
	 * @return
	 */
	public abstract ProjectMetadata getProjectMetadata();

	/**
	 * @param defectList
	 * @return
	 */
	public abstract Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList);

	/**
	 * @return
	 */
	public abstract String getProductNames();
	
	/**
	 * @return
	 */
	public abstract boolean hasValidCredentials();
	
	/**
	 * @return
	 */
	public abstract boolean hasValidProjectName();

	/**
	 * @param vulnerabilities
	 * @param metadata
	 * @return
	 */
	protected String makeDescription(final List<Vulnerability> vulnerabilities, final DefectMetadata metadata) {

		final StringBuffer stringBuilder = new StringBuffer(128);

		final String preamble = metadata.getPreamble();

		if (preamble != null && !"".equals(preamble)) {
			stringBuilder.append("General information\n");
			stringBuilder.append(preamble);
			stringBuilder.append('\n');
		}

		int vulnIndex = 0;

		if (vulnerabilities != null) {
			for (Vulnerability vulnerability : vulnerabilities) {

				stringBuilder.append("Vulnerability[" + vulnIndex + "]:\n" +
						vulnerability.getGenericVulnerability().getName() + '\n');

				final SurfaceLocation asl = vulnerability.getSurfaceLocation();
				stringBuilder.append("Vulnerability attack surface location:\n" +
										"URL: " + asl.getUrl() + "\n" +
										"Parameter: " + asl.getParameter() +
										"\n\n");
				
				vulnIndex++;
			}
		}
		return stringBuilder.toString();
	}

}
