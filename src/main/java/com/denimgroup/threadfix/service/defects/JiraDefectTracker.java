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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.XmlRpcCommonsTransportFactory;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * A defect tracking implementation for the JIRA bug tracker from Atlassian.
 * This is experimental at this point.
 * 
 * <a href="http://www.atlassian.com/software/jira/">JIRA Homepage</a>
 * 
 * TODO write update function
 * 
 * @author mcollins
 */
public class JiraDefectTracker extends AbstractDefectTracker {
	
	private String url;
	private String username;
	private String password;
	private String projectName;
	private String loginToken;
	
	/**
	 * Parse through the returned structure and return a hashmap of the results.
	 * 
	 * @param inputString
	 * @return
	 */
	public Map<String,String> getHash(String inputString) {
		Map<String,String> map = new HashMap<String, String>();
		int size = 0;
		String[] strArray = null;
		for (String s : inputString.split(",")) {
			strArray = s.split("=");
			size = strArray.length;
			if (strArray[0] != null) {
				strArray[0] = strArray[0].trim().replace("{", "");
			}

			if (size == 1) {
				map.put(strArray[0], null);
			} else if (size == 2) {
				map.put(strArray[0], strArray[1].replace("}", ""));
			}
		}

		return map;
	}

	/**
	 * @param projectName
	 * @param client
	 * @return
	 */
	private boolean projectExists(String projectName, XmlRpcClient client) {
		if (projectName == null)
			return false;
		// this is overloaded so we don't have to log in to use it
		try {
			List<String> loginTokenVector = new Vector<String>(2);
			loginTokenVector.add(loginToken);
			loginTokenVector.add(projectName);

			client.execute("jira1.getComponents", loginTokenVector);

		} catch (XmlRpcException e) {
			if (e.getMessage().contains("No project could be found")) {
				return false;
			} else {
				e.printStackTrace();
			}
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
			return false;
		}
		return true;
	}

	/**
	 * @param projectName
	 * @return
	 */
	private boolean projectExists(String projectName) {
		if (projectName == null)
			return false;
		XmlRpcClient client = initializeClient();
		login(client);
		return projectExists(projectName, client);
	}

	/**
	 * Initialize the connection to JIRA and log in.
	 * 
	 * The alternate TransportFactory stuff is required so that cookies work and
	 * the logins behave persistently
	 * 
	 * @return An initialized XmlRpcClient.
	 */
	private XmlRpcClient initializeClient() {

		XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();

		try {
			config.setServerURL(new URL(this.getUrlWithRpc()));
		} catch (MalformedURLException e) {
			log.error(String.format("Invalid URL for JIRA connection: '%1$s'.", url), e);
			return null;
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
			return null;
		}

		XmlRpcClient client = new XmlRpcClient();
		client.setConfig(config);
		client.setTransportFactory(new XmlRpcCommonsTransportFactory(client));

		return client;
	}

	/**
	 * Logs in to the JIRA system.
	 * 
	 * @param client
	 *            The initialized client.
	 * @return A login token for the authenticated session.
	 */
	private String login(XmlRpcClient client) {

		// Log in
		List<String> parameters = new ArrayList<String>(2);
		parameters.add(this.getUsername());
		parameters.add(this.getPassword());

		loginToken = null;

		try {
			loginToken = (String) client.execute("jira1.login", parameters);
			log.debug(String.format("JIRA returned log in token '%1$s'.", loginToken));
		} catch (XmlRpcException e) {
			String message = "Error logging in to JIRA. Check credentials?";
			log.error(message, e);
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
		}

		if (loginToken == null || loginToken.equals("")) {
			String message = "JIRA returned a null or empty login token.";
			log.warn(message);
			return LOGIN_FAILURE_STRING;
		} else {
			log.info("Successfully logged into JIRA repository.");
			return loginToken;
		}
	}

	/**
	 * Logs out of the JIRA repository.
	 * 
	 * @param client
	 *            Initialized and logged in client.
	 * @param loginToken
	 *            The log in token.
	 */
	private void logout(XmlRpcClient client, String loginToken) {
		Boolean result = false;
		try {
			result = (Boolean) client.execute("jira1.logout", new Object[] { loginToken });
		} catch (XmlRpcException e) {
			String msg = "Error while logging out of JIRA repository.";
			log.error(msg, e);
			return;
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
			return;
		}

		if (result) {
			log.info("Successfully logged out of JIRA.");
		} else {
			log.warn("JIRA returned false on logout. " + "No transport errors occured.");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.defects.AbstractDefectTracker#createDefect
	 * (com.denimgroup .threadfix.data.entities.Vulnerability[],
	 * com.denimgroup.threadfix.service.defects.DefectMetadata)
	 */
	@Override
	public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
		String jiraId = null;

		// TODO Make an actual exception handling routine here
		try {
			// Prepare to make a call
			XmlRpcClient client = initializeClient();
			login(client);

			if (this.loginToken == null) {
				return null;
			}

			if (!projectExists(projectName, client)) {
				log.error("Project did not exist");
				return null;
			}

			// Create bug
			String description = makeDescription(vulnerabilities, metadata);

			String summary = metadata.getDescription();

			Map<String, String> bugMap = new HashMap<String, String>();
			bugMap.put("project", projectName);
			bugMap.put("type", "1");
			bugMap.put("summary", summary);
			bugMap.put("assignee", "dgtestuser");
			bugMap.put("reporter", "dgtestuser");
			bugMap.put("description", description);

			List<Object> createVector = new Vector<Object>(2);
			createVector.add(loginToken);
			createVector.add(bugMap);

			@SuppressWarnings("unchecked")
			Map<String,String> actualResult = (HashMap<String, String>) client.execute(
					"jira1.createIssue", createVector);
			String key = null;
			if (actualResult != null) {
				key = actualResult.get("key");
			}

			if (key != null && !key.trim().equals("")) {
				jiraId = key;
			}
		} catch (XmlRpcException e) {
			log.warn("XmlRpcException occured while creating Defect.", e);
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
		}

		return jiraId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.defects.AbstractDefectTracker#getStatus
	 * (com.denimgroup.threadfix .data.entities.Defect)
	 */
	@Override
	public String getStatus(Defect defect) {

		try {
			XmlRpcClient client = initializeClient();
			login(client);
			// Retrieve projects

			String defectId = defect.getNativeId();
			if (defectId == null) {
				return null;
			}

			List<String> updateVector = new Vector<String>(2);
			updateVector.add(loginToken);
			updateVector.add(defectId);

			// TODO once there is a good testing environment, rewrite to be more typesafe
			@SuppressWarnings("unchecked")
			Map<String,String> map = (HashMap<String, String>) client.execute(
					"jira1.getIssue", updateVector);

			logout(client, loginToken);

			String status = map.get("status");
			String retVal = "";
			// TODO improve the status symbols.
			if (status.equals("1")) {
				retVal = "Open";
			} else if (status.equals("3")) {
				retVal = "In Progress";
			} else if (status.equals("4")) {
				retVal = "Reopened";
			} else if (status.equals("6")) {
				retVal = "Closed";
			} else {
				retVal = status;
			}

			return retVal;
		} catch (XmlRpcException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			log.warn("Illegal argument exception encountered while trying to contact JIRA RPC endpoint - check URL.", e);
		}

		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.denimgroup.threadfix.service.defects.AbstractDefectTracker#
	 * getMultipleDefectStatus(java .util.List)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
		// TODO Test this method - no Jira instance was available at the time of
		// writing.
		if (defectList == null) {
			return null;
		}

		XmlRpcClient client = initializeClient();
		if (client == null) {
			return null;
		}

		String loginToken = login(client);
		if (loginToken == null) {
			return null;
		}

		Map<Defect, Boolean> returnMap = new HashMap<Defect, Boolean>();

		for (Defect defect : defectList) {
			String defectId = defect.getNativeId();
			if (defectId == null) {
				return null;
			}

			List<String> updateVector = new Vector<String>(2);
			updateVector.add(loginToken);
			updateVector.add(defectId);

			Map<String,String> map = null;
			try {
				map = (HashMap<String, String>) client.execute("jira1.getIssue", updateVector);
			} catch (XmlRpcException e) {
				e.printStackTrace();
			}

			if (map != null) {
				String status = map.get("status");
				Boolean openStatus = null;
				// TODO improve the status symbols.
				if (status.equals("1")) {
					openStatus = true;
				} else if (status.equals("3")) {
					openStatus = true;
				} else if (status.equals("4")) {
					openStatus = true;
				} else if (status.equals("6")) {
					openStatus = false;
				}
				
				if (openStatus != null) {
					returnMap.put(defect, openStatus);
				}
			}
		}

		return returnMap;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.denimgroup.threadfix.service.defects.AbstractDefectTracker#
	 * getTrackerError()
	 */
	@Override
	public String getTrackerError() {
		// Prepare to make a call
		XmlRpcClient client = initializeClient();
		login(client);

		if (this.loginToken == null)
			return LOGIN_FAILURE_STRING;

		if (projectName == null || projectName.trim().equals(""))
			return "Project name was blank - check credentials.";

		if (!projectExists(projectName, client)) {
			return "The project specified does not exist - please specify a different one or "
					+ "create " + projectName + " in Jira.";
		}

		return null;
	}

	/**
	 * @return
	 */
	public String getUrlWithRpc() {
		if (url == null || url.trim().equals("")) {
			return null;
		}

		if (url.contains("rpc/xmlrpc")) {
			return url;
		}

		String tempUrl = url.trim();
		if (tempUrl.endsWith("/")) {
			tempUrl = tempUrl.concat("rpc/xmlrpc");
		} else {
			tempUrl = tempUrl.concat("/rpc/xmlrpc");
		}

		return tempUrl;
	}

	/**
	 * @return
	 */
	public String getUrl() {
		return url;
	}

	/**
	 * @param url
	 */
	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * @return
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * @param username
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * @return
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * @param password
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * @return
	 */
	public String getProjectName() {
		return projectName;
	}

	/**
	 * @param projectName
	 */
	public void setProjectName(String projectName) {
		this.projectName = projectName;
	}

	@Override
	public String getProductNames() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		if (LOGIN_FAILURE_STRING.equals(status)) {
			return "Authentication failed";
		}

		boolean projectStatus = projectExists(this.getProjectName(), client);

		if (projectStatus)
			return "Connection successful.";
		else
			return "Project not found.";
	}

	@Override
	public ProjectMetadata getProjectMetadata() {
		return null;
	}

	@Override
	public String getProjectIdByName() {
		return null;
	}

	@Override
	public boolean hasValidCredentials() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		return !LOGIN_FAILURE_STRING.equals(status);
	}

	@Override
	public boolean hasValidProjectName() {
		return projectExists(projectName);
	}
	
	@Override
	public String getInitialStatusString() {
		// TODO Figure out what the actual string is
		return "OPEN";
	}
	
	// TODO
	@Override
	public String getBugURL(String endpointURL, String bugID) {
		return endpointURL;
	}

}
