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
 * @author dcornell
 * @author mcollins
 */
public class BugzillaDefectTracker extends AbstractDefectTracker {
		
	private static Map<String, String> versionMap = new HashMap<>();
	
	private List<String> statuses = new ArrayList<>();
	private List<String> components = new ArrayList<>();
	private List<String> severities = new ArrayList<>();
	private List<String> versions = new ArrayList<>();
	private List<String> priorities = new ArrayList<>();

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
			if (loginStatus.equals(LOGIN_FAILURE) 
					|| loginStatus.equals(BAD_CONFIGURATION)) {
				log.warn("Login Failed, check credentials");
				return null;
			}

			if (!projectExists(projectName, client)) {
				log.warn("The project name wasn't found on the server.");
				return null;
			}

			String description = makeDescription(vulnerabilities, metadata);
			if (description.length() > 65500) {
				description = description.substring(0, 65499);
			}
			
			if (metadata.getDescription() == null    || metadata.getComponent() == null
					|| metadata.getVersion() == null || metadata.getSeverity() == null 
					|| metadata.getStatus() == null  || metadata.getPriority() == null) {
				return null;
			}

			Map<String, String> bugMap = new HashMap<>();
			bugMap.put("product", projectName);
			bugMap.put("component", metadata.getComponent());
			bugMap.put("summary", metadata.getDescription());
			bugMap.put("version", metadata.getVersion());
			bugMap.put("description", description);
			bugMap.put("op_sys", "All");
			bugMap.put("platform", "All");
			bugMap.put("priority", metadata.getPriority());
			bugMap.put("severity", metadata.getSeverity());
			bugMap.put("status", metadata.getStatus());

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
			log.error("Got IllegalArgumentException.", e2);
		}

		return bugzillaId;
	}

	/**
	 * Retrieve all the variable fields that Bugzilla installations have.
	 * 
	 * @param productId
	 * @return
	 */
	@Override
	public ProjectMetadata getProjectMetadata() {
		getPermissibleBugFieldValues();
		
		return new ProjectMetadata(components, versions, 
				severities, statuses, priorities);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {

		Map<String, Defect> idDefectMap = new HashMap<>();
		
		for (Defect defect : defectList) {
			if (defect != null && defect.getNativeId() != null) {
				idDefectMap.put(defect.getNativeId(), defect);
			}
		}
		
		Map<String, Object[]> queryMap = new HashMap<>();
		queryMap.put("ids", idDefectMap.keySet().toArray(
				new Object[idDefectMap.keySet().size()]));

		Object queryResult = executeMethod("Bug.get", new Object[] { queryMap });
		
		Map<Defect, Boolean> returnList = new HashMap<>();

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
				
				Integer id = (Integer) currentBugHash.get("id");
				
				if (idDefectMap.containsKey(id.toString()) &&
						idDefectMap.get(id.toString()) != null) {
					Defect defect = idDefectMap.get(id.toString());
					
					if (result instanceof String) {
						defect.setStatus((String) result);
					}
					
					returnList.put(defect, isOpen);
				}
			}
		} else {
			log.error("Expected a HashMap return value, but got something else instead.");
		}
		
		return returnList;
	}

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
		if (loginStatus.equals(LOGIN_FAILURE) 
				|| loginStatus.equals(BAD_CONFIGURATION)) {
			return "Bugzilla login failed, check your credentials.";
		}

		if (!projectExists(projectName, client)) {
			return "The project specified does not exist - please specify a different"
					+ " one or create " + projectName + " in Bugzilla.";
		}

		return null;
	}
	
	private void getPermissibleBugFieldValues(){ 
		client = initializeClient();
		
		String loginResponse = login(client);
		if (loginResponse == null) {
			return;
		}
		if (loginResponse.equals(LOGIN_FAILURE) 
				|| loginResponse.equals(BAD_CONFIGURATION)) {
			log.warn("Login Failed, check credentials");
			return;
		}
		
		Map<String, String> bugMap = new HashMap<>();
		bugMap.put("field", "bug_severity");
		Object[] bugArray = new Object[] { bugMap };
		Object createResult = executeMethod("Bug.legal_values", bugArray);
		severities.addAll(getValues(createResult));
		
		bugMap.put("field", "bug_status");
		bugArray = new Object[] { bugMap }; // maybe useless line
		createResult = executeMethod("Bug.legal_values", bugArray);
		statuses.addAll(getValues(createResult));
		
		if (statuses.contains("UNCONFIRMED")) {
			statuses.remove("UNCONFIRMED");
		}
		
		bugMap.put("field", "priority");
		bugArray = new Object[] { bugMap }; // maybe useless line
		createResult = executeMethod("Bug.legal_values", bugArray);
		priorities.addAll(getValues(createResult));
		
		projectId = getProjectIdByName();
		
		Map<String, String> queryMap = new HashMap<>();
		queryMap.put("field", "version");
		queryMap.put("product_id", projectId);
		createResult = executeMethod("Bug.legal_values", new Object[] { queryMap });
		versions.addAll(getValues(createResult));
		
		queryMap = new HashMap<>();
		queryMap.put("field", "component");
		queryMap.put("product_id", projectId);
		createResult = executeMethod("Bug.legal_values", new Object[] { queryMap });
		components.addAll(getValues(createResult));
	}

	/**
	 * If the Object given is a map containing a mapping for "values" to
	 * an object array containing string values, this method will return
	 * a List containing those items.
	 * @param rpcResponse
	 * @return
	 */
	private List<String> getValues(Object rpcResponse) {
		List<String> responseList = new ArrayList<>();
		if (rpcResponse != null && rpcResponse instanceof HashMap) {
			Map<?, ?> returnedData = (HashMap<?, ?>) rpcResponse;
			Object componentsObject = returnedData.get("values");
			if (componentsObject != null && componentsObject instanceof Object[]) {
				Object[] componentsArray = (Object[]) componentsObject;
				for (int i = 0; i < componentsArray.length; i++) {
					if (componentsArray[i] != null) {
						responseList.add(componentsArray[i].toString());
					}
				}
			}
		}
		return responseList;
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
		XmlRpcCommonsTransportFactory factory = new XmlRpcCommonsTransportFactory(client);
		factory.setHttpClient(new HttpClient());
		client.setTransportFactory(factory);

		return client;
	}

	/**
	 * @param client
	 * @throws XmlRpcException
	 */
	private String login(XmlRpcClient client) {

		Map<String, String> loginMap = new HashMap<>();
		loginMap.put("login", this.username);
		loginMap.put("password", this.password);
		loginMap.put("rememberlogin", "Bugzilla_remember");

		Object[] loginArray = new Object[1];
		loginArray[0] = loginMap;

		Object loginResult = null;
		try {
			loginResult = client.execute("User.login", loginArray);
		} catch (XmlRpcException e) {
			if (e.getMessage().contains("The username or password you entered is not valid")) {
				return LOGIN_FAILURE;
			}
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			if (e2.getMessage().contains("Host name may not be null")) {
				return BAD_CONFIGURATION;
			} else {
				e2.printStackTrace();
				return BAD_CONFIGURATION;
			}
		}

		if (loginResult == null) {
			return null;
		} else {
			return loginResult.toString();
		}
	}
	
	private XmlRpcClient client = null;
	private Object executeMethod(String method, Object[] params) {
		if (method == null || params == null)
			return null;
		
		if (client == null) {
			client = initializeClient();
			String loginResponse = login(client);
			if (loginResponse == null) {
				return null;
			}
			if (loginResponse.equals(LOGIN_FAILURE) 
					|| loginResponse.equals(BAD_CONFIGURATION)) {
				log.warn("Login Failed, check credentials");
				return null;
			}
		}
		
		if (client == null) {
			log.warn("There was an error initializing the Bugzilla client.");
			return null;
		}
		
		try {
			return client.execute(method, params);
		} catch (XmlRpcException e) {
			e.printStackTrace();
		}

		return null;
	}

	public String getVersion() {
		if (versionMap.get(url) != null) {
			return versionMap.get(url);
		}
		
		Object createResult = executeMethod("Bugzilla.version", new Object[] {});
				
		if (createResult instanceof Map<?,?>) {
			Map<?,?> item = (Map<?,?>) createResult;
			if (item.get("version") != null) {
				log.info("Bugzilla instance is version " + item.get("version"));
				versionMap.put(url, item.get("version").toString());
			}
		}
		return versionMap.get(url);
	}

	/**
	 * @param projectName
	 * @param client
	 * @return
	 */
	public boolean projectExists(String projectName, XmlRpcClient client) {
		this.projectName = projectName;
		return getProjectIdByName() != null;
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
			
			Map<String,Object[]> params = new HashMap<>();
			params.put("ids", ids);

			Map<String,Object[]> productMap = (HashMap<String, Object[]>) client.execute(
					"Product.get", new Object[] { params });
			Object[] products = productMap.get("products");
			
			for (Object item : products) {
				Map<String,Object> product = (HashMap<String, Object>) item;
				String productName = (String) product.get("name");
				buffer.append(productName).append(',');
			}

			productList = buffer.toString();
			productList = productList.substring(0, productList.length() - 1);
		} catch (XmlRpcException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			if (e2.getMessage().contains("Host name may not be null")) {
				return BAD_CONFIGURATION;
			} else {
				e2.printStackTrace();
				return BAD_CONFIGURATION;
			}
		}
		if(productList == ""){
			setLastError("There were problems communicating with the Bugzilla server.");
			return "Authentication failed";
		}

		return productList;
	}

	public String getProjectIdByName() {
		String version = getVersion();
		
		if (version == null) {
			log.info("Unable to get Bugzilla version. Exiting.");
		} else if (version.charAt(0) == '3') {
			return getProjectIdByNameVersion3();
		} else if (version.charAt(0) == '4'){
			return getProjectIdByNameVersion4();
		} else {
			log.warn("Bugzilla version was not 3 or 4, exiting.");
		}
		return null;
	}
	
	@SuppressWarnings("unchecked")
	private String getProjectIdByNameVersion3() {
		if (projectName == null)
			return null;
		
		XmlRpcClient client = initializeClient();
		String status = login(client);
		
		if (status == null || status.equals(LOGIN_FAILURE) || 
				status.equals(BAD_CONFIGURATION)) {
			log.warn(status);
			return null;
		}

		try {
			Map<String,Object[]> productsMap = (HashMap<String, Object[]>) client.execute(
					"Product.get_enterable_products", new Object[] {});
			Object[] ids = productsMap.get("ids");

			Map<String,Object[]> params = new HashMap<>();
			params.put("ids", ids);

			Map<String, Object[]> productMap = (HashMap<String, Object[]>) client.execute(
					"Product.get", new Object[] { params });
			Object[] products = productMap.get("products");
			if (products == null)
				return null;
			for (int i = 0; i < products.length; i++) {
				Map<String,Object> product = (HashMap<String, Object>) products[i];
				String productName = (String) product.get("name");
				if (projectName.equals(productName)) {
					Integer temp = (Integer) product.get("id");
					projectId = Integer.toString(temp);
					return projectId;
				}
			}
		} catch (XmlRpcException xre) {
			xre.printStackTrace();
		} catch (IllegalArgumentException e2) {
			return null;
		}
		return null;
	}
	
	private String getProjectIdByNameVersion4() {
		if (client == null) {
			client = initializeClient();
		}
		String status = login(client);
		
		if (status == null || status.equals(LOGIN_FAILURE) || 
				status.equals(BAD_CONFIGURATION)) {
			log.warn(status);
			return null;
		}
		
		// get Product info
		Map<String, Object[]> bugMap = new HashMap<>();
		Object[] names = new Object[] { projectName };
		bugMap.put("names", names);
		Object[] bugArray = new Object[] { bugMap };

		Object createResult = executeMethod("Product.get", bugArray);
		if (createResult != null && createResult instanceof Map<?, ?>) {
			Map<?, ?> mapVersion = (Map<?, ?>) createResult;
			if (mapVersion.containsKey("products")) {
				Object result = mapVersion.get("products");
				if (result instanceof Object[]) {
					Object[] stuff = (Object[]) result;
					for (Object item : stuff) {
						if (item instanceof Map<?, ?>) {
							Map<?,?> map = (Map<?,?>) item;
							if (map.get("id") != null) {
								return map.get("id").toString();
							}
						}
					}
				}
			}
		}
		
		return null;
	}

	@Override
	public String getProductNames() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		if (LOGIN_FAILURE.equals(status) || BAD_CONFIGURATION.equals(status)) {
			lastError = status;
			return null;
		} else {
			return getProducts(client);
		}
	}

	@Override
	public boolean hasValidCredentials() {
		XmlRpcClient client = initializeClient();
		String status = login(client);

		return !LOGIN_FAILURE.equals(status) 
				&& !BAD_CONFIGURATION.equals(status);
	}

	@Override
	public boolean hasValidProjectName() {
		if (projectName == null) {
			return false;
		}
		
		XmlRpcClient client = initializeClient();
		return projectExists(projectName, client);
	}

	@Override
	public String getBugURL(String endpointURL, String bugID) {
		if (endpointURL != null && bugID != null && endpointURL.endsWith("xmlrpc.cgi")) {
			return endpointURL.replace("xmlrpc.cgi", "show_bug.cgi?id="+bugID);
		} else  if (endpointURL != null) {
			if (endpointURL.endsWith("/")) {
				return endpointURL + "show_bug.cgi?id=" + bugID;
			} else {
				return endpointURL + "/show_bug.cgi?id=" + bugID;
			}
		} else {
			log.error("getBugURL() in BugzillaDefectTracker was given a null endpointURL.");
			return null;
		}
	}

	@Override
	public boolean hasValidUrl() {
		log.info("Checking Bugzilla URL.");
		XmlRpcClient client = initializeClient();
		
		Map<String, String> loginMap = new HashMap<>();
		loginMap.put("login", " ");
		loginMap.put("password", " ");
		loginMap.put("rememberlogin", "Bugzilla_remember");

		Object[] loginArray = new Object[1];
		loginArray[0] = loginMap;

		try {
			client.execute("User.login", loginArray);
			log.warn("Shouldn't be here, we just logged into " +
					 "Bugzilla with blank username / password.");
			return true;
		} catch (XmlRpcException e) {
			if (e.getMessage().contains("The username or password you entered is not valid")) {
				log.info("The URL was good, received an authentication warning.");
				return true;
			} else if (e.getMessage().contains(
					"I/O error while communicating with HTTP server")) {
				log.warn("Unable to retrieve a RPC response from that URL. Returning false.");
				return false;
			} else {
				log.warn("Something went wrong. Check out the error. Returning false.", e);
				return false;
			}
		} catch (IllegalArgumentException e2) {
			log.warn("IllegalArgumentException was tripped. Returning false.");
			return false;
		}
	}
	
	public String getServerURLWithRpc() {
		if (url == null || url.trim().equals("")) {
			return null;
		}
	
		if (url.contains("xmlrpc.cgi")) {
			return url;
		}
	
		String tempUrl = url.trim();
		if (tempUrl.endsWith("/")) {
			tempUrl = tempUrl.concat("xmlrpc.cgi");
		} else {
			tempUrl = tempUrl.concat("/xmlrpc.cgi");
		}
	
		return tempUrl;
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<Defect> getDefectList() {		
		
		XmlRpcClient client = initializeClient();
		if (client == null) {
			return null;
		}

		String loginStatus = login(client);
		if (loginStatus == null) {
			return null;
		}

		// TODO Pass this information back to the user
		if (loginStatus.equals(LOGIN_FAILURE) 
				|| loginStatus.equals(BAD_CONFIGURATION)) {
			log.warn("Login Failed, check credentials");
			return null;
		}		
		
		List<Defect> returnList = new ArrayList<>();
		Map<String, String> queryMap = new HashMap<>();
		queryMap.put("product", projectName);

		Object queryResult = executeMethod("Bug.search", new Object[] { queryMap });
		if (queryResult instanceof HashMap) {
			Map<String,Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
			Object[] bugsArray = returnedData.get("bugs");
			for (int i = 0; i < bugsArray.length; i++) {
				Object currentBug = bugsArray[i];
				Map<String,Object> currentBugHash = (HashMap<String, Object>) currentBug;
				if (currentBugHash == null) {
					continue;
				}			
				Integer id = (Integer) currentBugHash.get("id");
				Defect d = new Defect();
				d.setNativeId(String.valueOf(id));
				returnList.add(d);				
			}
		} else {
			log.error("Expected a HashMap return value, but got something else instead.");
		}
		
		return returnList;
	}
}
