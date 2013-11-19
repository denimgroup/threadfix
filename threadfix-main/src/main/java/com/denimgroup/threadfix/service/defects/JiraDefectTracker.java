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
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLHandshakeException;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * This class has been rewritten to use the JIRA REST interface and may not work on older
 * JIRA installations. However, it should actually be functional now.
 * 
 * <a href="http://www.atlassian.com/software/jira/">JIRA Homepage</a>
 * 
 * @author mcollins
 */
public class JiraDefectTracker extends AbstractDefectTracker {
	
	// The double slash is the Jira newline wiki syntax.
	private static final String newLineRegex = "\\\\n", 
			doubleSlashNewLine = " \\\\\\\\\\\\\\\\ ";
				
	// HELPER METHODS
	
	// I want to parse this into a java.net.URL object and then work with it, but I'm 
	// not sure how that would work out with a non-atlassian hosted install.
	private String getUrlWithRest() {
		if (getUrl() == null || getUrl().trim().equals("")) {
			return null;
		}
		
		try {
			new URL(getUrl());
		} catch (MalformedURLException e) {
			setLastError("The URL format was bad.");
			return null;
		}

		if (getUrl().endsWith("rest/api/2/")) {
			return getUrl();
		}
		
		String tempUrl = getUrl().trim();
		if (tempUrl.endsWith("/")) {
			tempUrl = tempUrl.concat("rest/api/2/");
		} else {
			tempUrl = tempUrl.concat("/rest/api/2/");
		}

		return tempUrl;
	}
	
	/**
	 * 
	 * @param urlString JIRA URL to connect to
	 * @return true if we get an HTTP 401, false if we get another HTTP response code (such as 200:OK)
	 * 		or if an exception occurs
	 */
	private boolean requestHas401Error(String urlString) {
		log.info("Checking to see if we get an HTTP 401 error for the JIRA URL '" + urlString + "'");
		
		boolean retVal;
		
		try {
			URL url = new URL(urlString);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.setDoOutput(true);
			
			if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
				retVal = true;
			} else {
				log.info("Got a non-401 HTTP repsonse code of: " + connection.getResponseCode());
				retVal = false;
			}
		} catch (MalformedURLException e) {
			log.warn("JIRA URL string of '" + urlString + "' is not a valid URL.", e);
			setLastError(BAD_URL);
			retVal = false;
		} catch (SSLHandshakeException e) {
			log.warn("Certificate Error encountered while trying to find the response code.", e);
			setLastError(INVALID_CERTIFICATE);
			retVal = false;
		} catch (IOException e) {
			log.warn("IOException encountered while trying to find the response code: " + e.getMessage(), e);
			setLastError(IO_ERROR);
			retVal = false;
		}
		
		log.info("Return value will be " + retVal);
		
		return retVal;
	}
	
	private boolean hasXSeraphLoginReason() {
		URL url = null;
		try {
			url = new URL(getUrlWithRest() + "user?username=" + getUsername());
		} catch (MalformedURLException e) {
			e.printStackTrace();
			return false;
		}

		try {
			HttpURLConnection httpConnection = (HttpURLConnection) url.openConnection();

			RestUtils.setupAuthorization(httpConnection, username, password);
			
			httpConnection.addRequestProperty("Content-Type", "application/json");
			httpConnection.addRequestProperty("Accept", "application/json");
			
			String headerResult = httpConnection.getHeaderField("X-Seraph-LoginReason");

			return headerResult != null && headerResult.equals("AUTHENTICATION_DENIED");
		} catch (IOException e) {
			log.warn("IOException encountered while trying to find the response code.", e);
		}
		return false;
	}
	
	private List<String> getNamesFromList(String path) {
		String result = RestUtils.getUrlAsString(getUrlWithRest() + path, username, password);

		List<String> names = new ArrayList<>();
		
		if (result != null) {
			JSONArray returnArray = RestUtils.getJSONArray(result);
		
			for (int i = 0; i < returnArray.length(); i++) {
				try {
					names.add(returnArray.getJSONObject(i).getString("name"));
				} catch (JSONException e) {
					e.printStackTrace();
				}
			}
			return names;
		}
		return null;
	}
	
	private Map<String,String> getNameFieldMap(String path, String field) {
		String result = RestUtils.getUrlAsString(getUrlWithRest() + path, username, password);
		
		if (result == null) {
			return null;
		}
		
		JSONArray returnArray = RestUtils.getJSONArray(result);
		
		Map<String,String> nameFieldMap = new HashMap<>();
		
		for (int i = 0; i < returnArray.length(); i++) {
			try {
				nameFieldMap.put(returnArray.getJSONObject(i).getString("name"), 
								returnArray.getJSONObject(i).getString(field));
			} catch (JSONException e) {
				e.printStackTrace();
			}
		}
		
		return nameFieldMap;
	}
	
	// CHECKS FOR VALID CONFIGURATION
	
	@Override
	public boolean hasValidCredentials() {
		log.info("Checking JIRA credentials.");
		lastError = null;
		
		String response = RestUtils.getUrlAsString(getUrlWithRest() + "user?username=" + 
											getUsername(),getUsername(),getPassword());
		
		try {
			boolean valid = response != null && RestUtils.getJSONObject(response) != null && 
					RestUtils.getJSONObject(response).getString("name").equals(getUsername());
			if (valid) {
				log.info("JIRA Credentials are valid.");
			} else {
				log.info("JIRA Credentials are invalid.");
			}
			
			if (hasXSeraphLoginReason()) {
				lastError = "JIRA CAPTCHA protection has been tripped. Please log in at " + url + " to continue.";
			}
						
			return valid;
		} catch (JSONException e) {
			log.warn("JIRA credentials check did not return JSON, something is wrong.", e);
			return false;
		}
	}

	@Override
	public boolean hasValidProjectName() {
		if (projectName == null)
			return false;
		
		return getNamesFromList("project").contains(projectName);
	}

	@Override
	public boolean hasValidUrl() {
		log.info("Checking JIRA RPC Endpoint URL.");
		
		if (getUrlWithRest() == null) {
			log.info("URL was invalid.");
			return false;
		}

		boolean valid = requestHas401Error(getUrlWithRest() + "user");
		
		if (valid) {
			log.info("JIRA URL was valid, returned 401 response as expected because we do not yet have credentials.");
		} else {
			log.warn("JIRA URL was invalid or some other problem occurred, 401 response was expected but not returned.");
		}
		
		return valid;
	}

	// PRE-SUBMISSION METHODS
	
	@Override
	public String getProductNames() {
		
		lastError = null;
	
		Map<String, String> nameIdMap = getNameFieldMap("project/","key");
		
		if (nameIdMap != null && nameIdMap.size() > 0) {
			StringBuilder builder = new StringBuilder();
			
			for (String name : nameIdMap.keySet()) {
				builder.append(name);
				builder.append(',');
			}
			return builder.substring(0,builder.length()-1);
		} else {
			if (!hasValidUrl()) {
				lastError = "Supplied endpoint was invalid.";
			} else if (hasXSeraphLoginReason()) {
				lastError = "JIRA CAPTCHA protection has been tripped. Please log in at " + url + " to continue.";
			} else if (!hasValidCredentials()) {
				lastError = "Invalid username / password combination";
			} else if (nameIdMap != null) {
				lastError = "No projects were found. Check your JIRA instance.";
			} else {
				lastError = "Not sure what the error is.";
			}
			
			return null;
		}
	}
	
	@Override
	public String getLastError() {
		return lastError;
	}

	@Override
	public ProjectMetadata getProjectMetadata() {
		if (getProjectId() == null)
			setProjectId(getProjectIdByName());
		List<String> components = getNamesFromList("project/" + projectId + "/components");
		List<String> blankList = Arrays.asList("-");
		List<String> statusList = Arrays.asList("Open");
		List<String> priorities = getNamesFromList("priority");
		
		if (components == null || components.isEmpty()) {
			components = Arrays.asList("-");
		}
		
		return new ProjectMetadata(components, blankList,
				blankList, statusList, priorities);
	}

	@Override
	public String getProjectIdByName() {
		Map<String,String> projectNameIdMap = getNameFieldMap("project/","key");
		
		if (projectNameIdMap == null) {
			return null;
		} else {
			return projectNameIdMap.get(projectName);
		}
	}
	
	// CREATION AND STATUS UPDATE METHODS

	@Override
	public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
		
		if (getProjectId() == null) {
			setProjectId(getProjectIdByName());
		}
		
		Map<String,String> priorityHash = getNameFieldMap("priority", "id"),
				           componentsHash = getNameFieldMap("project/" + projectId + "/components", "id"),
				           projectsHash = getNameFieldMap("project","id");
		
		String description = makeDescription(vulnerabilities, metadata);
		
		//	TODO - Use a better JSON API to construct the JSON message. JSONObject.quote() is nice
		//	and all, but...
		String payload = "{ \"fields\": {" +
				" \"project\": { \"id\": " + JSONObject.quote(projectsHash.get(getProjectName())) + " }," +
				" \"summary\": " + JSONObject.quote(metadata.getDescription()) + "," +
				" \"issuetype\": { \"id\": \"1\" }," +
				" \"assignee\": { \"name\":" + JSONObject.quote(username) + " }," +
				" \"reporter\": { \"name\": " + JSONObject.quote(username) + " }," +
				" \"priority\": { \"id\": " + JSONObject.quote(priorityHash.get(metadata.getPriority())) + " }," +
				" \"description\": " + JSONObject.quote(description);

		if (metadata.getComponent() != null && !metadata.getComponent().equals("-")) {
			payload += "," + " \"components\": [ { \"id\": " + 
					JSONObject.quote(componentsHash.get(metadata.getComponent())) + " } ]";
		}
				
		payload += " } }";
		
		payload = payload.replaceAll(newLineRegex, doubleSlashNewLine);
				
		String result = RestUtils.postUrlAsString(getUrlWithRest() + "issue",payload,getUsername(),getPassword());
		String id = null;
		try {
			if (result != null && RestUtils.getJSONObject(result) != null &&
					RestUtils.getJSONObject(result).getString("key") != null) {
				id = RestUtils.getJSONObject(result).getString("key");
			}
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return id;
	}

	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
		
		Map<Defect,Boolean> returnMap = new HashMap<>();
		
		if (defectList != null && defectList.size() != 0) {
			log.info("Updating JIRA defect status for " + defectList.size() + " defects.");
			for (Defect defect : defectList) {
				if (defect != null) {
					String result = getStatus(defect);
					boolean isOpen = result != null && (!result.equals("Resolved") || !result.equals("Closed"));
					returnMap.put(defect, isOpen);
				}
			}
		} else {
			log.info("Tried to update defects but no defects were found.");
		}

		return returnMap;
	}

	private String getStatus(Defect defect) {
		if (defect == null || defect.getNativeId() == null) {
			log.warn("Bad defect passed to getStatus()");
			return null;
		}
		
		log.info("Updating status for defect " + defect.getNativeId());
		
		String result = RestUtils.getUrlAsString(getUrlWithRest() + "issue/" + defect.getNativeId(), 
				getUsername(), getPassword());
		
		if (result != null) {
			try {
				JSONObject resultObject = new JSONObject(result);
				if (resultObject.getJSONObject("fields") != null
						&& resultObject.getJSONObject("fields").getJSONObject("status") != null
						&& resultObject.getJSONObject("fields").getJSONObject("status").getString("name") != null) {
					
					String status = resultObject.getJSONObject("fields").getJSONObject("status").getString("name");
					log.info("Current status for defect " + defect.getNativeId() + " is " + status);
					defect.setStatus(status);
					return status;
				}
			} catch (JSONException e) {
				log.warn("JSON parsing failed when trying to get defect status.");
			}
		}
		
		return null;
	}
	
	@Override
	public String getTrackerError() {
		log.info("Attempting to find the reason that JIRA integration failed.");
		
		String reason = null;
		
		if (!hasValidUrl()) {
			reason =  "The JIRA url was incorrect.";
		} else if (!hasValidCredentials()) {
			reason =  "The supplied credentials were incorrect.";
		} else if (!hasValidProjectName()) {
			reason =  "The project name was invalid.";
		} else {
			reason = "The JIRA integration failed but the " +
					 "cause is not the URL, credentials, or the Project Name.";
		}
		
		log.info(reason);
		return reason;
	}

	@Override
	public String getBugURL(String endpointURL, String bugID) {
		String returnString = endpointURL;
		
		if (endpointURL.endsWith("rest/api/2/")) {
			returnString = endpointURL.replace("rest/api/2/", "browse/" + bugID);
		} else if (endpointURL.endsWith("/")) {
			returnString = endpointURL + "browse/" + bugID;
		} else {
			returnString = endpointURL + "/browse/" + bugID;
		}
		
		return returnString;
	}

	@Override
	public List<Defect> getDefectList() {		
			
		String payload = "{\"jql\":\"project='" + projectName + "'\",\"fields\":[\"key\"]}";			
		String result = RestUtils.postUrlAsString(getUrlWithRest() + "search",payload,getUsername(),getPassword());
		List<Defect> defectList = new ArrayList<>();
		try {
		String str = RestUtils.getJSONObject(result).getString("issues");
		
		JSONArray returnArray = RestUtils.getJSONArray(str);
		
		for (int i = 0; i < returnArray.length(); i++) {
			
				Defect d = new Defect();
				d.setNativeId(returnArray.getJSONObject(i).getString("key"));
				defectList.add(d);
		}
			} catch (JSONException e) {
				log.warn("JSON parsing failed when trying to get defect list.");
			}
					
		return defectList;
	}

}
