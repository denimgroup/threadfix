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

import com.denimgroup.threadfix.data.entities.Defect;
import com.denimgroup.threadfix.data.entities.Vulnerability;
import com.denimgroup.threadfix.service.defects.utils.bugzilla.BugzillaClient;
import com.denimgroup.threadfix.service.defects.utils.bugzilla.BugzillaClientImpl;
import com.denimgroup.threadfix.viewmodel.DefectMetadata;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.apache.xmlrpc.XmlRpcException;

import javax.annotation.Nonnull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * @author dcornell
 * @author mcollins
 */
public class BugzillaDefectTracker extends AbstractDefectTracker {
		
	private static Map<String, String> versionMap = new HashMap<>();

    BugzillaClient bugzillaClient = BugzillaClientImpl.getInstance();

	private List<String> statuses = list();
	private List<String> components = list();
	private List<String> severities = list();
	private List<String> versions = list();
	private List<String> priorities = list();

    private BugzillaClient.ConnectionStatus configureClientAndGetStatus() {

        BugzillaClient.ConnectionStatus status = null;
        try {
            status = bugzillaClient.configure(getServerURLWithRpc(), username, password);
        } catch (XmlRpcException e) {
            setLastError(e.getMessage());
            return BugzillaClient.ConnectionStatus.INVALID;
        }

        if (status != BugzillaClient.ConnectionStatus.VALID) {
            log.error("Received Bugzilla connection status " + status + ", please fix the error before continuing.");
        }
        return status;
    }

	@Override
	public String createDefect(List<Vulnerability> vulnerabilities, DefectMetadata metadata) {
		String bugzillaId = null;

		// TODO Better handle error cases
		try {

            if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
                return null;
            }

			if (!projectExists(projectName)) {
				log.warn("The project name wasn't found on the server.");
				return null;
			}

            String description = metadata.getFullDescription();

			if (description.length() > 65500) {
				description = description.substring(0, 65499);
			}
			
			if (metadata.getDescription() == null    || metadata.getComponent() == null
					|| metadata.getVersion() == null || metadata.getSeverity() == null 
					|| metadata.getStatus() == null  || metadata.getPriority() == null) {
                log.error("DefectMetadata was missing a field. Please fix this and try again.");

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

			Map<String, Integer> actualResult = bugzillaClient.createBug(bugMap);

			Integer returnId = actualResult.get("id");
			bugzillaId = returnId.toString();
		} catch (IllegalArgumentException e2) {
			log.error("Got IllegalArgumentException.", e2);
		} catch (XmlRpcException e) {
            log.error("Got XmlRpcException.", e);
        }

		return bugzillaId;
	}

	/**
	 * Retrieve all the variable fields that Bugzilla installations have.
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
        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return null;
        }

		Map<String, Defect> idDefectMap = new HashMap<>();
		
		for (Defect defect : defectList) {
			if (defect != null && defect.getNativeId() != null) {
				idDefectMap.put(defect.getNativeId(), defect);
			}
		}
		
		Map<String, Object[]> queryMap = new HashMap<>();
		queryMap.put("ids", idDefectMap.keySet().toArray(
				new Object[idDefectMap.keySet().size()]));

        Object queryResult = null;
        try {
            queryResult = bugzillaClient.executeMethod("Bug.get", queryMap);
        } catch (XmlRpcException e) {
            log.error("Encountered XmlRpcException while trying to get bug information", e);
        }

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
			log.error("Expected a HashMap return value, but got something else instead: " + queryResult);
		}
		
		return returnList;
	}

	@Override
	public String getTrackerError() {
        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return null;
        }

		if (!projectExists(projectName)) {
			return "The project specified does not exist - please specify a different"
					+ " one or create " + projectName + " in Bugzilla.";
		}

		return null;
	}
	
	private void getPermissibleBugFieldValues(){
        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return;
        }

        try {
            Map<String, String> bugMap = new HashMap<>();
            bugMap.put("field", "bug_severity");
            Object[] bugArray = new Object[] { bugMap };
            Object createResult = bugzillaClient.executeMethod("Bug.legal_values", bugArray);
            severities.addAll(getValues(createResult));

            bugMap.put("field", "bug_status");
            bugArray = new Object[] { bugMap }; // maybe useless line
            createResult = bugzillaClient.executeMethod("Bug.legal_values", bugArray);
            statuses.addAll(getValues(createResult));

            if (statuses.contains("UNCONFIRMED")) {
                statuses.remove("UNCONFIRMED");
            }

            bugMap.put("field", "priority");
            createResult = bugzillaClient.executeMethod("Bug.legal_values", bugMap);
            priorities.addAll(getValues(createResult));

            projectId = getProjectIdByName();

            Map<String, String> queryMap = new HashMap<>();
            queryMap.put("field", "version");
            queryMap.put("product_id", projectId);
            createResult = bugzillaClient.executeMethod("Bug.legal_values", queryMap);
            versions.addAll(getValues(createResult));

            queryMap = new HashMap<>();
            queryMap.put("field", "component");
            queryMap.put("product_id", projectId);
            createResult = bugzillaClient.executeMethod("Bug.legal_values", queryMap);
            components.addAll(getValues(createResult));
        } catch (XmlRpcException e) {
            log.error("Encountered XmlRpcException while trying to read fields from Bugzilla.", e);
        }
	}

	/**
	 * If the Object given is a map containing a mapping for "values" to
	 * an object array containing string values, this method will return
	 * a List containing those items.
	 * @param rpcResponse
	 * @return
	 */
	private List<String> getValues(Object rpcResponse) {
		List<String> responseList = list();
		if (rpcResponse != null && rpcResponse instanceof HashMap) {
			Map<?, ?> returnedData = (HashMap<?, ?>) rpcResponse;
			Object componentsObject = returnedData.get("values");
			if (componentsObject != null && componentsObject instanceof Object[]) {
				Object[] componentsArray = (Object[]) componentsObject;
                for (Object component : componentsArray) {
                    if (component != null) {
                        responseList.add(component.toString());
                    }
                }
			}
		}
		return responseList;
	}
	
	public String getVersion() {
		if (versionMap.get(url) != null) {
			return versionMap.get(url);
		}

        Object createResult = null;
        try {
            createResult = bugzillaClient.executeMethod("Bugzilla.version");
        } catch (XmlRpcException e) {
            log.error("Got XmlRpcException while trying to get the bugzilla version.", e);
        }

        if (createResult instanceof Map<?,?>) {
			Map<?,?> item = (Map<?,?>) createResult;
			if (item.get("version") != null) {
				log.info("Bugzilla instance is version " + item.get("version"));
				versionMap.put(url, item.get("version").toString());
			}
		}
		return versionMap.get(url);
	}

	public boolean projectExists(String projectName) {
		this.projectName = projectName;
		return getProjectIdByName() != null;
	}

	@SuppressWarnings("unchecked")
    @Nonnull
	private List<String> getProducts() {
        List<String> returnList = list();

		try {
			Map<String,Object[]> productsMap = (HashMap<String, Object[]>) bugzillaClient.executeMethod(
                    "Product.get_accessible_products");
			Object[] ids = productsMap.get("ids");


			Map<String,Object[]> params = new HashMap<>();
			params.put("ids", ids);

			Map<String,Object[]> productMap = (HashMap<String, Object[]>) bugzillaClient.executeMethod(
					"Product.get", params);
			Object[] products = productMap.get("products");
			
			for (Object item : products) {
				Map<String,Object> product = (HashMap<String, Object>) item;
				String productName = (String) product.get("name");
                returnList.add(productName);
			}

		} catch (XmlRpcException e) {
            log.error(e.getMessage());
            setLastError(e.getMessage());
            return list(e.getMessage());
//			e.printStackTrace();
		} catch (IllegalArgumentException e2) {
			if (e2.getMessage().contains("Host name may not be null")) {
				return list(BAD_CONFIGURATION);
			} else {
				e2.printStackTrace();
				return list(BAD_CONFIGURATION);
			}
		}
		if (returnList.isEmpty()){
			setLastError("There were problems communicating with the Bugzilla server.");
			return list("Authentication failed");
		}

		return returnList;
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

        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return null;
        }

		try {
			Map<String,Object[]> productsMap = (HashMap<String, Object[]>) bugzillaClient.executeMethod(
					"Product.get_enterable_products");
			Object[] ids = productsMap.get("ids");

			Map<String,Object[]> params = new HashMap<>();
			params.put("ids", ids);

			Map<String, Object[]> productMap = (HashMap<String, Object[]>) bugzillaClient.executeMethod(
					"Product.get", params);
			Object[] products = productMap.get("products");
			if (products == null)
				return null;
            for (Object product1 : products) {
                Map<String, Object> product = (HashMap<String, Object>) product1;
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
        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return null;
        }

		// get Product info
		Map<String, Object[]> bugMap = new HashMap<>();
		bugMap.put("names", new Object[] { projectName });

        Object createResult = null;
        try {
            createResult = bugzillaClient.executeMethod("Product.get", bugMap);
        } catch (XmlRpcException e) {
            log.error("Encountered XmlRpcException while getting project information.", e);
        }
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

	@Nonnull
    @Override
	public List<String> getProductNames() {
        BugzillaClient.ConnectionStatus status = configureClientAndGetStatus();

		if (status == BugzillaClient.ConnectionStatus.INVALID) {
			if (getLastError() == null || getLastError().isEmpty())
                setLastError(status.toString());
			return list();
		} else {
            setLastError(null);
			return getProducts();
		}
	}

	@Override
	public boolean hasValidCredentials() {
		return configureClientAndGetStatus() == BugzillaClient.ConnectionStatus.VALID;
	}

	@Override
	public boolean hasValidProjectName() {
		return projectName != null && projectExists(projectName);
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
		return bugzillaClient.checkUrl(getServerURLWithRpc());
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

        if (configureClientAndGetStatus() != BugzillaClient.ConnectionStatus.VALID) {
            return null;
        }
		
		List<Defect> returnList = list();
		Map<String, String> queryMap = new HashMap<>();
		queryMap.put("product", projectName);

        Object queryResult;

        try {
            queryResult = bugzillaClient.executeMethod("Bug.search", queryMap);
        } catch (XmlRpcException e) {
            log.error("Encountered XmlRpcException while getting defect information");
            return list(); // TODO see if this is the right thing
        }

        if (queryResult instanceof HashMap) {
			Map<String,Object[]> returnedData = (HashMap<String, Object[]>) queryResult;
			Object[] bugsArray = returnedData.get("bugs");
            for (Object currentBug : bugsArray) {
                Map<String, Object> currentBugHash = (HashMap<String, Object>) currentBug;
                if (currentBugHash == null) {
                    continue;
                }
                Integer id = (Integer) currentBugHash.get("id");
                Defect defect = new Defect();
                defect.setNativeId(String.valueOf(id));
                returnList.add(defect);
            }
		} else {
			log.error("Expected a HashMap return value, but got something else instead.");
		}
		
		return returnList;
	}
}
