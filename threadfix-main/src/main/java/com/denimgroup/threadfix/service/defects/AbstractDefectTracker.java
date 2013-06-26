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
package com.denimgroup.threadfix.service.defects;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.SanitizedLogger;

/**
 * An abstract class providing a base implementation of a defect tracker. This
 * class should be extended by platform specific trackers.
 * 
 * @author jraim
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
	 * Return a list of available product names. The credentials and URL need to be set
	 * for this method to work.
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
	public abstract String getTrackerError();

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
						vulnerability.getGenericVulnerability().getName() + '\n' +
						"CWE-ID: " + vulnerability.getGenericVulnerability().getId() + '\n' + 
						"http://cwe.mitre.org/data/definitions/" + 
						vulnerability.getGenericVulnerability().getId() + ".html" + '\n');

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
	
	//The following methods help with REST interfaces.
	protected InputStream getUrl(String urlString, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
		InputStream is = null;
		HttpURLConnection httpConnection;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");

			is = httpConnection.getInputStream();
			
			return is;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return is;
	}
	
	protected String getUrlAsString(String urlString, String username, String password) {
		InputStream responseStream = getUrl(urlString,username,password);
		
		if (responseStream == null) {
			return null;
		}
		
		String test = null;
		try {
			test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			closeInputStream(responseStream);
		}
		
		return test;
	}
	
	protected void closeInputStream(InputStream stream) {
		if (stream != null) {
			try {
				stream.close();
			} catch (IOException ex) {
				log.warn("Closing an input stream failed.", ex);
			}
		}
	}
	
	protected InputStream postUrl(String urlString, String data, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			log.warn("URL used for POST was bad: '" + urlString + "'");
			return null;
		}
		
		HttpURLConnection httpConnection = null;
		OutputStreamWriter outputWriter = null;
		try {
			httpConnection = (HttpURLConnection) url.openConnection();

			setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");
			
			httpConnection.setDoOutput(true);
			outputWriter = new OutputStreamWriter(httpConnection.getOutputStream());
		    outputWriter.write(data);
		    outputWriter.flush();

			InputStream is = httpConnection.getInputStream();
			
			return is;
		} catch (IOException e) {
			log.warn("IOException encountered trying to post to URL with message: " + e.getMessage());
			if(httpConnection == null) {
				log.warn("HTTP connection was null so we cannot do further debugging of why the HTTP request failed");
			} else {
				try {
					InputStream errorStream = httpConnection.getErrorStream();
					if(errorStream == null) {
						log.warn("Error stream from HTTP connection was null");
					} else {
						log.warn("Error stream from HTTP connection was not null. Attempting to get response text.");
						String postErrorResponse = IOUtils.toString(errorStream);
						log.warn("Error text in response was '" + postErrorResponse + "'");
					}
				} catch (IOException e2) {
					log.warn("IOException encountered trying to read the reason for the previous IOException: "
								+ e2.getMessage(), e2);
				}
			}
		} finally {
			if (outputWriter != null) {
				try {
					outputWriter.close();
				} catch (IOException e) {
					log.warn("Failed to close output stream in postUrl.", e);
				}
			}
		}
		
		return null;
	}
	
	protected String postUrlAsString(String urlString, String data, String username, String password) {
		InputStream responseStream = postUrl(urlString,data,username,password);
		
		if (responseStream == null) {
			return null;
		}
		
		String test = null;
		try {
			test = IOUtils.toString(responseStream);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			closeInputStream(responseStream);
		}
		
		return test;
	}
	
	protected void setupAuthorization(HttpURLConnection connection,
			String username, String password) {
		String login = username + ":" + password;
		String encodedLogin = new String(Base64.encodeBase64(login.getBytes()));
		//String encodedLogin = Base64.encodeBase64String(login.getBytes());
		connection.setRequestProperty("Authorization", "Basic " + encodedLogin);
	}
	
	protected JSONArray getJSONArray(String responseContents) {
		try {
			return new JSONArray(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.", e);
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param responseContents
	 * @return
	 */
	protected JSONObject getJSONObject(String responseContents) {
		try {
			return new JSONObject(responseContents);
		} catch (JSONException e) {
			log.warn("JSON Parsing failed.", e);
			return null;
		}
	}
	
	/**
	 * Convenience method to wrap the exception catching.
	 * @param object
	 * @return
	 */
	protected Integer getId(JSONObject object) {
		try {
			return object.getInt("id");
		} catch (JSONException e) {
			log.warn("Failed when trying to parse an ID out of the object.", e);
			return null;
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
