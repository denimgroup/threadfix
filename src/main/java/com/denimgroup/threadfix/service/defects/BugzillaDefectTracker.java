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

import org.apache.commons.httpclient.HttpClient;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.XmlRpcCommonsTransportFactory;

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;

/**
 * This provides an example of creating and checking the status of defects in
 * Bugzilla.
 * 
 * TODO write update function
 * 
 * @author dcornell
 */
public class BugzillaDefectTracker extends AbstractDefectTracker {
	
	private String serverURL;
	private String serverUsername;
	private String serverPassword;
	private String serverProject;
	private String serverProjectId;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.defects.AbstractDefectTracker#createDefect
	 * com.denimgroup.threadfix.data.entities.Vulnerability,
	 * com.denimgroup.threadfix.service.defects.DefectMetadata)
	 */
	@Override
	public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
		String bugzillaId = null;

		// TODO Better handle error cases
		try {
			XmlRpcClient client = initializeClient();
			if (client == null) {
				return null;
			}

			String loginStatus = login(client);
			if (loginStatus == null) {
				return null;
			}

			// TODO Pass this information back to the user
			if (loginStatus.equals(LOGIN_FAILURE_STRING) || loginStatus.equals(INCORRECT_CONFIGURATION)) {
				log.warn("Login Failed, check credentials");
				return null;
			}

			if (!projectExists(serverProject, client)) {
				log.warn("The project name wasn't found on the server.");
				return null;
			}

			String description = makeDescription(vulnerabilities, metadata);
			if (description.length() > 65500) {
				description = description.substring(0, 65499);
			}

			String summary = metadata.getDescription();
			String component = metadata.getComponent();
			String version = metadata.getVersion();
			String severity = metadata.getSeverity();

			Map<String, String> bugMap = new HashMap<String, String>();
			bugMap.put("product", serverProject);
			bugMap.put("component", component);
			bugMap.put("summary", summary);
			bugMap.put("version", version);
			bugMap.put("description", description);
			bugMap.put("op_sys", "All");
			bugMap.put("platform", "PC");
			bugMap.put("priority", "P5");
			bugMap.put("severity", severity);
			bugMap.put("status", "NEW");

			Object[] bugArray = new Object[1];
			bugArray[0] = bugMap;

			Object createResult = client.execute("Bug.create", bugArray);
			log.debug("Create result: " + createResult);

			@SuppressWarnings("unchecked")
			Map<String, Integer> actualResult = (HashMap<String, Integer>) createResult;
			Integer returnId = actualResult.get("id");
			bugzillaId = returnId.toString();
		} catch (XmlRpcException e) {
			log.debug("Exception occured while creating Defect: " + e.getMessage());
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			log.error(e2);
		}

		return bugzillaId;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * com.denimgroup.threadfix.service.defects.AbstractDefectTracker#getStatus
	 * (com.denimgroup.threadfix .data.entities.Defect)
	 */
	@SuppressWarnings("unchecked")
	@Override
	public String getStatus(Defect defect) {
		if (defect == null) {
			return null;
		}

		String retVal = null;

		try {
			XmlRpcClient client = initializeClient();
			if (client == null) {
				return null;
			}

			String loginStatus = login(client);
			if (loginStatus == null) {
				return null;
			}

			// Check the status of a bug
			Map<String, String> queryMap = new HashMap<String, String>();

			// This is supposed to be an array of bug IDs, but that causes
			// serialization issues
			// on the client side that then cause fault issues on Bugzilla that
			// results in an
			// invalid
			// fault code that then causes deserialization problems on the
			// client side. Exhausting.
			//
			// So the trick now would be to make it so you can access multiple
			// bugs at once
			// I tried "2, 3" and "[2, 3]" with no luck - those aren't valid bug
			// ids when they hit
			// Bugzilla server-side.
			// For now we'll do this one at a time
			queryMap.put("ids", defect.getNativeId());

			Object queryResult = null;
			queryResult = client.execute("Bug.get", new Object[] { queryMap });

			if (queryResult instanceof HashMap) {
				Map<String, Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
				Object[] bugsArray = returnedData.get("bugs");

				for (int i = 0; i < bugsArray.length; i++) {
					Object currentBug = bugsArray[i];
					Map<String, Object> currentBugHash = (HashMap<String, Object>) currentBug;
					Boolean isOpen = (Boolean) currentBugHash.get("is_open");

					if (isOpen) {
						retVal = "OPEN";
					} else {
						retVal = "CLOSED";
					}
				}
			} else {
				log.error("Expected a HashMap return value, but got something else instead.");
			}
		} catch (XmlRpcException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			log.error(e2);
		}

		return retVal;
	}

	/**
	 * Retrieve all components of a product
	 * 
	 * @param productId
	 * @return
	 */
	@SuppressWarnings("unchecked")
	@Override
	public ProjectMetadata getProjectMetadata() {
		XmlRpcClient client = initializeClient();

		List<String> projectComponents = new ArrayList<String>();
		List<String> projectVersions = new ArrayList<String>();
		List<String> projectSeverities = new ArrayList<String>();
		Map<String,String> queryMap = new HashMap<String, String>();

		try {
			queryMap.put("field", "component");
			queryMap.put("product_id", serverProjectId);
			Object queryResult = client.execute("Bug.legal_values", new Object[] { queryMap });
			if (queryResult instanceof HashMap) {
				Map<String, Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
				Object[] componentsArray = returnedData.get("values");
				for (int i = 0; i < componentsArray.length; i++) {
					projectComponents.add((String) componentsArray[i]);
				}
			}

			queryMap = new HashMap<String, String>();
			queryMap.put("field", "version");
			queryMap.put("product_id", serverProjectId);
			queryResult = client.execute("Bug.legal_values", new Object[] { queryMap });
			if (queryResult instanceof HashMap) {
				Map<String, Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
				Object[] versionsArray = returnedData.get("values");
				for (int i = 0; i < versionsArray.length; i++) {
					projectVersions.add((String) versionsArray[i]);
				}
			}

			queryMap = new HashMap<String, String>();
			queryMap.put("field", "severity");
			queryMap.put("product_id", serverProjectId);
			queryResult = client.execute("Bug.legal_values", new Object[] { queryMap });
			if (queryResult instanceof HashMap) {
				Map<String,Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
				Object[] severitiesArray = returnedData.get("values");
				for (int i = 0; i < severitiesArray.length; i++) {
					projectSeverities.add((String) severitiesArray[i]);
				}
			}

		} catch (XmlRpcException xre) {
			log.error("Exception occurred while retrieve the components of a project: "
					+ xre.getMessage());
			xre.printStackTrace();
		}  catch (IllegalArgumentException e2) {
			log.error(e2);
		}

		return new ProjectMetadata(projectComponents, projectVersions, projectSeverities);
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
		if (defectList == null) {
			return null;
		}

		XmlRpcClient client = initializeClient();
		if (client == null) {
			return null;
		}

		String loginStatus = login(client);
		if (loginStatus == null) {
			return null;
		}

		Map<Defect, Boolean> returnList = new HashMap<Defect, Boolean>();

		for (Defect defect : defectList) {
			Map<String, String> queryMap = new HashMap<String, String>();
			queryMap.put("ids", defect.getNativeId());

			Object queryResult = null;
			try {
				queryResult = client.execute("Bug.get", new Object[] { queryMap });
			} catch (XmlRpcException e) {
				// TODO make this more meaningful - now it just moves on to the
				// next one
				e.printStackTrace();
				continue;
			} catch (IllegalArgumentException e2) {
				log.error(e2);
				continue;
			}

			if (queryResult instanceof HashMap) {
				Map<String,Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
				Object[] bugsArray = returnedData.get("bugs");
				for (int i = 0; i < bugsArray.length; i++) {
					Object currentBug = bugsArray[i];
					Map<String,Object> currentBugHash = (HashMap<String, Object>) currentBug;
					if (currentBugHash == null) {
						continue;
					}

					Boolean isOpen = (Boolean) currentBugHash.get("is_open");
					
					Object result = currentBugHash.get("status");
					if (result instanceof String) {
						defect.setStatus((String) result);
					}
					
					returnList.put(defect, isOpen);
				}
			} else {
				log.error("Expected a HashMap return value, but got something else instead.");
			}
		}
		return returnList;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.denimgroup.threadfix.service.defects.AbstractDefectTracker#
	 * getTrackerError()
	 */
	@Override
	public String getTrackerError() {
		XmlRpcClient client = initializeClient();
		if (client == null) {
			return null;
		}
		String loginStatus = login(client);
		if (loginStatus == null) {
			return null;
		}

		// TODO Pass this information back to the user
		if (loginStatus.equals(LOGIN_FAILURE_STRING) || loginStatus.equals(INCORRECT_CONFIGURATION)) {
			return "Bugzilla login failed, check your credentials.";
		}

		if (!projectExists(serverProject, client)) {
			return "The project specified does not exist - please specify a different one or "
					+ "create " + serverProject + " in Bugzilla.";
		}

		return null;
	}

	/**
	 * Set up the configuration
	 * 
	 * @return
	 * @throws MalformedURLException
	 */
	private XmlRpcClient initializeClient() {

		// Get the RPC client set up and ready to go
		// The alternate TransportFactory stuff is required so that cookies
		// work and the logins behave persistently

		XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
		try {
			config.setServerURL(new URL(this.getServerURLWithRpc()));
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}

		// config.setEnabledForExtensions(true);
		XmlRpcClient client = new XmlRpcClient();
		client.setConfig(config);

		HttpClient httpClient = new HttpClient();
		XmlRpcCommonsTransportFactory factory = new XmlRpcCommonsTransportFactory(client);
		factory.getClass();
		httpClient.getClass();
		factory.setHttpClient(httpClient);
		client.setTransportFactory(factory);

		return client;
	}

	/**
	 * @param client
	 * @throws XmlRpcException
	 */
	private String login(XmlRpcClient client) {

		// Log in
		Map<String, String> loginMap = new HashMap<String, String>();
		loginMap.put("login", this.serverUsername);
		loginMap.put("password", this.serverPassword);
		loginMap.put("rememberlogin", "Bugzilla_remember");

		Object[] loginArray = new Object[1];
		loginArray[0] = loginMap;

		Object loginResult = null;
		try {
			loginResult = client.execute("User.login", loginArray);
		} catch (XmlRpcException e) {
			if (e.getMessage().contains("The username or password you entered is not valid")) {
				return LOGIN_FAILURE_STRING;
			}
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			if (e2.getMessage().contains("Host name may not be null")) {
				return INCORRECT_CONFIGURATION;
			} else {
				e2.printStackTrace();
				return INCORRECT_CONFIGURATION;
			}
		}

		if (loginResult == null) {
			return null;
		} else {
			return loginResult.toString();
		}
	}

	/**
	 * @return
	 */
	public String getServerURLWithRpc() {
		if (serverURL == null || serverURL.trim().equals("")) {
			return null;
		}

		if (serverURL.contains("xmlrpc.cgi")) {
			return serverURL;
		}

		String tempUrl = serverURL.trim();
		if (tempUrl.endsWith("/")) {
			tempUrl = tempUrl.concat("xmlrpc.cgi");
		} else {
			tempUrl = tempUrl.concat("/xmlrpc.cgi");
		}

		return tempUrl;
	}

	/**
	 * @return
	 */
	public String getServerURL() {
		return serverURL;
	}

	/**
	 * @param serverURL
	 */
	public void setServerURL(String serverURL) {
		this.serverURL = serverURL;
	}

	/**
	 * @return
	 */
	public String getServerProject() {
		return serverProject;
	}

	/**
	 * @param serverProject
	 */
	public void setServerProject(String serverProject) {
		this.serverProject = serverProject;
	}

	/**
	 * @return
	 */
	public String getServerProjectId() {
		return serverProjectId;
	}

	/**
	 * @param serverProject
	 */
	public void setServerProjectId(String serverProjectId) {
		this.serverProjectId = serverProjectId;
	}

	/**
	 * @return
	 */
	public String getServerUsername() {
		return serverUsername;
	}

	/**
	 * @param serverUsername
	 */
	public void setServerUsername(String serverUsername) {
		this.serverUsername = serverUsername;
	}

	/**
	 * @return
	 */
	public String getServerPassword() {
		return serverPassword;
	}

	/**
	 * @param serverPassword
	 */
	public void setServerPassword(String serverPassword) {
		this.serverPassword = serverPassword;
	}

	/**
	 * @param projectName
	 * @param client
	 * @return
	 * @throws XmlRpcException
	 */
	@SuppressWarnings("unchecked")
	public boolean projectExists(String projectName, XmlRpcClient client) {
		if (projectName == null)
			return false;
		
		Map<String,Object[]> productsMap = null;
		try {
			productsMap = (HashMap<String, Object[]>) client.execute(
					"Product.get_accessible_products", new Object[] {});
			Object[] ids = productsMap.get("ids");
	
			for (Object i : ids) {
				Map<String,Object[]> params = new HashMap<String, Object[]>();
				params.put("ids", new Object[] { i });
	
				Map<String,Object[]> productMap = (HashMap<String, Object[]>) client.execute(
						"Product.get", new Object[] { params });
				Object[] products = productMap.get("products");
				Map<String,Object> product = (HashMap<String, Object>) products[0];
				String productName = (String) product.get("name");
				if (productName != null && projectName.equals(productName)) {
					return true;
				}
			}
		} catch (XmlRpcException e) {
			log.warn("The RPC connection encountered an error while trying to check a Bugzilla product name.", e);
			return false;
		} catch (IllegalArgumentException e2) {
			log.error("Encountered an error while trying to check a Bugzilla product name. Check the URL.", e2);
			return false;
		}
		
		return false;
	}

	/**
	 * @param client
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private String getProducts(XmlRpcClient client) {
		String productList = "";

		try {
			Map<String,Object[]> productsMap = (HashMap<String, Object[]>) client.execute(
					"Product.get_accessible_products", new Object[] {});
			Object[] ids = productsMap.get("ids");

			StringBuffer buffer = new StringBuffer();
			for (Object i : ids) {
				Map<String,Object[]> params = new HashMap<String, Object[]>();
				params.put("ids", new Object[] { i });

				Map<String,Object[]> productMap = (HashMap<String, Object[]>) client.execute(
						"Product.get", new Object[] { params });
				Object[] products = productMap.get("products");
				Map<String,Object> product = (HashMap<String, Object>) products[0];
				String productName = (String) product.get("name");
				buffer.append(productName).append(',');
			}
			productList = buffer.toString();
			productList = productList.substring(0, productList.length() - 1);
		} catch (XmlRpcException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			if (e2.getMessage().contains("Host name may not be null")) {
				return INCORRECT_CONFIGURATION;
			} else {
				e2.printStackTrace();
				return INCORRECT_CONFIGURATION;
			}
		}

		return productList;
	}

	@SuppressWarnings("unchecked")
	public String getProjectIdByName() {
		if (serverProject == null)
			return null;
		
		XmlRpcClient client = initializeClient();
		String status = login(client);
		
		if (status == null || status.equals(LOGIN_FAILURE_STRING) || status.equals(INCORRECT_CONFIGURATION)) {
			log.warn(status);
			return null;
		}

		try {
			Map<String,Object[]> productsMap = (HashMap<String, Object[]>) client.execute(
					"Product.get_accessible_products", new Object[] {});
			Object[] ids = productsMap.get("ids");

			Map<String,Object[]> params = new HashMap<String, Object[]>();
			params.put("ids", ids);

			Map<String, Object[]> productMap = (HashMap<String, Object[]>) client.execute(
					"Product.get", new Object[] { params });
			Object[] products = productMap.get("products");
			if (products == null)
				return null;
			for (int i = 0; i < products.length; i++) {
				Map<String,Object> product = (HashMap<String, Object>) products[i];
				String productName = (String) product.get("name");
				if (serverProject.equals(productName)) {
					Integer temp = (Integer) product.get("id");
					serverProjectId = Integer.toString(temp);
					return serverProjectId;
				}
			}
		} catch (XmlRpcException xre) {
			xre.printStackTrace();
		} catch (IllegalArgumentException e2) {
			return null;
		}
		return null;
	}

	@Override
	public String getProductNames() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		if (LOGIN_FAILURE_STRING.equals(status) || INCORRECT_CONFIGURATION.equals(status)) {
			return "Authentication failed";
		} else {
			return getProducts(client);
		}
	}

	@Override
	public boolean hasValidCredentials() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		return !LOGIN_FAILURE_STRING.equals(status) && !INCORRECT_CONFIGURATION.equals(status);
	}

	@Override
	public boolean hasValidProjectName() {
		XmlRpcClient client = initializeClient();
		return projectExists(serverProject, client);
	}

	@Override
	public String getInitialStatusString() {
		return "OPEN";
	}

	@Override
	public String getBugURL(String endpointURL, String bugID) {
		if (endpointURL != null && bugID != null && endpointURL.endsWith("xmlrpc.cgi")) {
			return endpointURL.replace("xmlrpc.cgi", "show_bug.cgi?id="+bugID);
		} else {
			return endpointURL + "show_bug.cgi?id=" + bugID;
		}
	}
}
