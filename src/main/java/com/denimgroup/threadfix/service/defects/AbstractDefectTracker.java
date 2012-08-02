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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

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
		HttpsURLConnection m_connect;
		try {
			m_connect = (HttpsURLConnection) url.openConnection();

			setupAuthorization(m_connect, username, password);
			
			m_connect.addRequestProperty("Content-Type", "application/json");
			m_connect.addRequestProperty("Accept", "application/json");

			is = m_connect.getInputStream();
			
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
		}
		
		return test;
	}
	
	protected InputStream postUrl(String urlString, String data, String username, String password) {
		URL url = null;
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return null;
		}
		
		HttpsURLConnection m_connect;
		try {
			m_connect = (HttpsURLConnection) url.openConnection();

			setupAuthorization(m_connect, username, password);
			
			m_connect.addRequestProperty("Content-Type", "application/json");
			m_connect.addRequestProperty("Accept", "application/json");
			
			m_connect.setDoOutput(true);
		    OutputStreamWriter wr = new OutputStreamWriter(m_connect.getOutputStream());
		    wr.write(data);
		    wr.flush();

			InputStream is = m_connect.getInputStream();
			
			return is;
		} catch (IOException e) {
			e.printStackTrace();
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
		}
		
		return test;
	}
	
	protected void setupAuthorization(HttpsURLConnection connection,
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
			log.warn("JSON Parsing failed.");
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
			log.warn("JSON Parsing failed.");
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
			log.warn("Failed when trying to parse an ID out of the object.");
			return null;
		}
	}

}
