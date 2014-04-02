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
package com.denimgroup.threadfix.service.defects;

import java.util.List;
import java.util.Map;

import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;

/**
 * An abstract class providing a base implementation of a defect tracker. This
 * class should be extended by platform specific trackers.
 * 
 * @author jraim
 * @author mcollins
 * 
 */
public abstract class AbstractDefectTracker {
	
	protected String url, username, password, projectName, projectId, lastError;

	protected final static String LOGIN_FAILURE = "Invalid username / password combination";
	protected final static String BAD_CONFIGURATION = "Your configuration is invalid: check your URL.";
	public final static String INVALID_CERTIFICATE = "The indicated server has an invalid or self-signed certificate.";
	public final static String BAD_URL = "The defect tracker URL is not valid.";
	public final static String IO_ERROR = "There were problems communicating with the defect tracker server.";
	
	// Common log for all Defect Tracker Exporters.
	protected final SanitizedLogger log = new SanitizedLogger(this.getClass());

	/**
	 * Take information from a list of vulnerabilities and the DefectMetadata bean and 
	 * create a Defect in the tracking system.
	 * 
	 * @param vulnerabilities
	 * @param metadata
     *
     * TODO return a better type than String
     *
	 * @return the native ID of the new defect. ThreadFix will handle the rest.
	 */
	public abstract String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata);

	/**
	 * Calculate and return the URL for the bug given the bug ID and the endpoint URL. Should be simple.
	 * 
	 * @param endpointURL
	 * @param bugID
	 * @return the URL for the bug
	 */
	public abstract String getBugURL(String endpointURL, String bugID);
	
	/**
	 * 
	 * Given a list of defects, check them over and return a map with the defects as keys
	 * and a boolean representing the open status of the defect. To set a more specific open status 
	 * for the Defects, use the Defect.setStatus() method.
	 * 
	 * TODO possibly re-architect this
	 * 
	 * @param defectList
	 * @return A map with keys from the input list and boolean outputs for open status
	 */
	public abstract Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList);
	
	/**
	 * 
	 * @return
	 */
	public abstract List<Defect> getDefectList();

	/**
	 * Return a list of available product names. The credentials and URL need to be set
	 * for this method to work.
     *
     * TODO Avoid strings where other types are more appropriate
     * We should create wrapper object with collection and error message
	 * 
	 * @return a comma separated string of available product names
	 */
	public abstract String getProductNames();
	
	/**
	 * Given the name of the project as the projectName field, return its ID. 
	 * If the ID is not important, just implement this method and return null.
	 * 
	 * @return
	 */
	public abstract String getProjectIdByName();

	/**
	 * ProjectMetadata is comprised of 5 List<String> objects. 
	 * Set as many or as few of them as are required. They are:
	 * statuses, components, severities, versions and priorities. 
	 * These choices will be presented to the user and the choices will come back 
	 * in the DefectMetadata bean for the createDefect() method.
	 * 
	 * @see ProjectMetadata
	 * @return a ProjectMetadata bean
	 */
	public abstract ProjectMetadata getProjectMetadata();

	/**
	 * This method is called after a failed defect submission in an attempt to try to diagnose errors.
	 * If this functionality is not important, returning a String literal will be fine.
	 * 
	 * @return
	 */
    public String getTrackerError() {
        log.info("Attempting to find the reason that Defect Tracker integration failed.");

        String reason;

        if (!hasValidUrl()) {
            reason =  "The Defect Tracker url was incorrect.";
        } else if (!hasValidCredentials()) {
            reason =  "The supplied credentials were incorrect.";
        } else if (!hasValidProjectName()) {
            reason =  "The project name was invalid.";
        } else {
            reason = "The Defect Tracker integration failed but the " +
                    "cause is not the URL, credentials, or the Project Name.";
        }

        log.info(reason);
        return reason;
    }

	/**
	 * Check the username and password fields against the url field for valid credentials.
	 * 
	 * @return
	 */
	public abstract boolean hasValidCredentials();
	
	/**
	 * Given a project name, url, and username / password, check the project name.
	 * 
	 * @return
	 */
	public abstract boolean hasValidProjectName();
	
	/**
	 * Check the URL for validity.
	 * 
	 */
	public abstract boolean hasValidUrl();

	/**
	 * @param vulnerabilities
	 * @param metadata
	 * @return
	 */
	protected String makeDescription(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {

		StringBuilder stringBuilder = new StringBuilder();

		String preamble = metadata.getPreamble();

		if (preamble != null && !"".equals(preamble)) {
			stringBuilder.append("General information\n");
			stringBuilder.append(preamble);
			stringBuilder.append('\n');
		}

		int vulnIndex = 0;

		if (vulnerabilities != null) {
			for (Vulnerability vulnerability : vulnerabilities) {
				if (vulnerability.getGenericVulnerability() != null &&
						vulnerability.getSurfaceLocation() != null) {

					stringBuilder.append("Vulnerability[" + vulnIndex + "]:\n" +
							vulnerability.getGenericVulnerability().getName() + '\n' +
							"CWE-ID: " + vulnerability.getGenericVulnerability().getId() + '\n' + 
							"http://cwe.mitre.org/data/definitions/" + 
							vulnerability.getGenericVulnerability().getId() + ".html" + '\n');
	
					SurfaceLocation surfaceLocation = vulnerability.getSurfaceLocation();
					stringBuilder.append("Vulnerability attack surface location:\n" +
											"URL: " + surfaceLocation.getUrl() + "\n" +
											"Parameter: " + surfaceLocation.getParameter());
					
					addNativeIds(vulnerability, stringBuilder);
					
					stringBuilder.append("\n\n");
					vulnIndex++;
				}
			}
		}
		return stringBuilder.toString();
	}
	
	private void addNativeIds(Vulnerability vulnerability, StringBuilder builder) {
		List<Finding> findings = vulnerability.getFindings();
		if (findings != null && !findings.isEmpty()) {
			for (Finding finding : findings) {
				if (finding != null && 
						finding.getScan() != null && 
						finding.getScan().getApplicationChannel() != null && 
						finding.getScan().getApplicationChannel().getChannelType() != null &&
						finding.getScan().getApplicationChannel().getChannelType().getName() != null) {
					String channelName = finding.getScan().getApplicationChannel().getChannelType().getName();
					if (ChannelType.NATIVE_ID_SCANNERS.contains(channelName)) {
						builder.append("\n" + channelName + " ID: " + finding.getNativeId());
					}
				}
			}
		}
	}
	
	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getProjectName() {
		return projectName;
	}

	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

	public String getProjectId() {
		return projectId;
	}

	public void setProjectId(String projectId) {
		this.projectId = projectId;
	}

	public String getLastError() {
		return lastError;
	}
	
	public void setLastError(String lastError) {
		this.lastError = lastError;
	}
}
