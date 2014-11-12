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
import com.denimgroup.threadfix.exception.DefectTrackerFormatException;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.viewmodel.DynamicFormField;
import com.denimgroup.threadfix.service.defects.utils.JsonUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtilsImpl;
import com.denimgroup.threadfix.service.defects.utils.jira.DefectPayload;
import com.denimgroup.threadfix.service.defects.utils.jira.DynamicFormFieldParser;
import com.denimgroup.threadfix.service.defects.utils.jira.UserRetriever;
import com.denimgroup.threadfix.service.defects.utils.jira.JiraJsonMetadataResponse;
import com.denimgroup.threadfix.viewmodel.ProjectMetadata;
import org.codehaus.jackson.map.ObjectMapper;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.listFrom;

/**
 * This class has been rewritten to use the JIRA REST interface and may not work on older
 * JIRA installations. However, it should actually be functional now.
 * 
 * <a href="http://www.atlassian.com/software/jira/">JIRA Homepage</a>
 * 
 * @author mcollins
 */
public class JiraDefectTracker extends AbstractDefectTracker {

    RestUtils restUtils = RestUtilsImpl.getInstance(JiraDefectTracker.class);

    // The double slash is the Jira newline wiki syntax.
    private static final String NEW_LINE_REGEX = "\\\\n",
            DOUBLE_SLASH_NEW_LINE = " \\\\\\\\\\\\\\\\ ",
            METADATA_EXTENSION = "issue/createmeta?issuetypeIds=1&expand=projects.issuetypes.fields&projectKeys=";

    private static final String CONTENT_TYPE = "application/json";

    // HELPER METHODS

    // I want to parse this into a java.net.URL object and then work with it, but I'm
    // not sure how that would work out with a non-atlassian hosted install.
    private String getUrlWithRest() {
        if (getUrl() == null || getUrl().trim().equals("")) {
            assert false;
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

    private List<String> getNamesFromList(String path) {
        String result = restUtils.getUrlAsString(getUrlWithRest() + path, username, password);

        List<String> names = list();

        if (result != null) {
            JSONArray returnArray = JsonUtils.getJSONArray(result);

            if (returnArray != null) {
                for (int i = 0; i < returnArray.length(); i++) {
                    try {
                        names.add(returnArray.getJSONObject(i).getString("name"));
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                }
            }
            return names;
        }
        assert false : "This method should only be called with a valid connection.";
        return null;
    }

    private Map<String, String> getNameFieldMap(String path, String field) {
        String result = restUtils.getUrlAsString(getUrlWithRest() + path, username, password);

        if (result == null) {
            assert false : "This method should only be called with a valid connection.";
            return null;
        }

        JSONArray returnArray = JsonUtils.getJSONArray(result);

        Map<String, String> nameFieldMap = new HashMap<>();

        if (returnArray != null) {
            for (int i = 0; i < returnArray.length(); i++) {
                try {
                    nameFieldMap.put(returnArray.getJSONObject(i).getString("name"),
                            returnArray.getJSONObject(i).getString(field));
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }
		
		return nameFieldMap;
	}
	
	// CHECKS FOR VALID CONFIGURATION
	
	@Override
	public boolean hasValidCredentials() {
		log.info("Checking JIRA credentials.");
		lastError = null;

        String urlString = getUrlWithRest() + "user?username=" + getUsername();
        String response;
        try {
            response = restUtils.getUrlAsString(urlString, getUsername(), getPassword());
        } catch (RestIOException e) {
            if (e.getStatusCode() == 401) {
                lastError = "Jira Credentials are invalid.";
                return false;
            }
            throw e;
        }

        boolean valid = false;
        String reason = null;

        if (response == null) {
            reason = "Null response was received from Jira server.";
        } else if (JsonUtils.getJSONObject(response) == null) {
            reason = "The REST response was not a valid JSON object.";

            // TODO this is dodgy--perhaps this is causing the error in GitHub issue 136?
        } else {
            String name = JsonUtils.getStringProperty(response, "name");
            if (name != null && name.equals(getUsername())) {
                valid = true;
                log.info("Name is " + name);
            } else {
                reason = "The returned name (" + name + ") did not match the username.";
            }
        }

        if (valid) {
            log.info("JIRA Credentials are valid.");
        } else {
            log.info("JIRA Credentials are invalid. Reason: " + reason);
            lastError = reason;
        }

        if (restUtils.hasXSeraphLoginReason(urlString, getUsername(), getPassword())) {
            lastError = "JIRA CAPTCHA protection has been tripped. Please log in at " + url + " to continue.";
        }

        return valid;
	}

	@Override
	public boolean hasValidProjectName() {
        return projectName != null && getNamesFromList("project").contains(projectName);
    }

	@Override
	public boolean hasValidUrl() {
		log.info("Checking JIRA RPC Endpoint URL.");
		
		if (getUrlWithRest() == null) {
			log.info("URL was invalid.");
			return false;
		}

		boolean valid = restUtils.requestHas401Error(getUrlWithRest() + "user");
		
		if (valid) {
            setLastError(BAD_URL);
			log.info("JIRA URL was valid, returned 401 response as expected because we do not yet have credentials.");
		} else {
			log.warn("JIRA URL was invalid or some other problem occurred, 401 response was expected but not returned.");
		}
		
		return valid;
	}

	// PRE-SUBMISSION METHODS
	
	@Nonnull
    @Override
	public List<String> getProductNames() {
		
		lastError = null;

        Map<String, String> nameIdMap;
        try {
            nameIdMap = getNameFieldMap("project/", "key");
        } catch (RestIOException e) {
            if (e.getStatusCode() == 401) {
                throw new RestIOException(e, "Invalid JIRA credentials, server returned 401 Unauthorized.");
            } else {
                throw e;
            }
        }

        if (!hasValidCredentials()) {
            lastError = "Invalid username / password combination";
            return list();
        }

		if (nameIdMap != null && nameIdMap.size() > 0) {
			return listFrom(nameIdMap.keySet());
		} else {
			if (!hasValidUrl()) {
				lastError = "Supplied endpoint was invalid.";
			} else if (restUtils.hasXSeraphLoginReason(getUrlWithRest() + "user?username=" + getUsername(),
                    getUsername(), getPassword())) {
				lastError = "JIRA CAPTCHA protection has been tripped. Please log in at " + url + " to continue.";
			} else if (nameIdMap != null) {
				lastError = "No projects were found. Check your JIRA instance.";
			} else {
				lastError = "Not sure what the error is.";
			}

			return list();
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

		return new ProjectMetadata(getDynamicFormFields());
	}

    List<DynamicFormField> getDynamicFormFields() {
        String response =
                restUtils.getUrlAsString(getUrlWithRest() + METADATA_EXTENSION + getProjectId(),
                            getUsername(), getPassword());

        log.debug(response);

        UserRetriever retriever = new UserRetriever(getUsername(), getPassword(), getProjectId(), getUrlWithRest(), restUtils);

        return DynamicFormFieldParser.getFields(response, retriever);
    }

    JiraJsonMetadataResponse.Project getJiraMetadata() {
        String response =
                restUtils.getUrlAsString(getUrlWithRest() + METADATA_EXTENSION + getProjectId(),
                            getUsername(), getPassword());

        log.debug(response);

        return DynamicFormFieldParser.getJiraProjectMetadata(response);
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

		String description = makeDescription(vulnerabilities, metadata);

        Map<String, Object> map = metadata.getFieldsMap();

        if (map.get("description") != null) {
            description = map.get("description") + "\n" + description;
        }

        map.put("description", description);

        String payload = getPayload(map);
        log.info("Payload: " + payload);

        String result, id = null;
        try {
            result = restUtils.postUrlAsString(getUrlWithRest() + "issue", payload, getUsername(), getPassword(), CONTENT_TYPE);
        } catch (RestIOException e) {
            // This exception will be thrown if Jira has fields that aren't allowed.
            log.info("Received RestIOException with message " + e.getMessage() +
                    ". Attempting to correct errors and resubmit.");

            // Trying to send request to Jira one more time, remove all error fields if any
            String errorResponseMsg = restUtils.getPostErrorResponse();
            List<String> errorFieldList = getErrorFieldList(errorResponseMsg);
            log.info("Trying to send request one more time to Jira without fields: " + errorFieldList.toString());
            result = restUtils.postUrlAsString(getUrlWithRest() + "issue", payload, getUsername(), getPassword(), CONTENT_TYPE);

            // if we got a result then it was a success, otherwise let's rethrow the exception
            if (result == null) {
                throw e;
            }
        }

        if (result != null) {
            id = JsonUtils.getStringProperty(result, "key");
        }

		return id;
	}

    private List<String> getErrorFieldList(String errorResponseMsg) {
        List<String> errorFieldList = list();
        if (errorResponseMsg != null && JsonUtils.getJSONObject(errorResponseMsg) != null) {
            String errorResponse = JsonUtils.getStringProperty(errorResponseMsg, "errors");
            if (errorResponse == null || errorResponse.isEmpty())
                return errorFieldList;
            String[] errorList = errorResponse.split("\\\",\\\"");
            for (String error : errorList) {
                if (error == null || error.isEmpty())
                    continue;
                String field = error.split("\\\":\\\"")[0];
                field = field.replace("{", "");
                field = field.replace("\\", "");
                field = field.replace("\"", "");
                errorFieldList.add(field);
            }
        }
        return errorFieldList;
    }

    private String getPayload(Map<String, Object> objectMap) {

        DefectPayload payload = new DefectPayload(objectMap, getJiraMetadata());

        try {
            return new ObjectMapper().writeValueAsString(payload);
        } catch (IOException e) {
            throw new DefectTrackerFormatException(e, "We were unable to serialize object as JSON");
        }
    }

    private boolean isValidField(List<String> errorFieldList, String field) {
        if (errorFieldList == null || errorFieldList.size() == 0)
            return true;
        return !errorFieldList.contains(field);
    }

	@Override
	public Map<Defect, Boolean> getMultipleDefectStatus(List<Defect> defectList) {
		
		Map<Defect,Boolean> returnMap = new HashMap<>();
		
		if (defectList != null && defectList.size() != 0) {
			log.info("Updating JIRA defect status for " + defectList.size() + " defects.");
			for (Defect defect : defectList) {
				if (defect != null) {
					String result = getStatus(defect);
					boolean isOpen = result != null && !(result.equals("Resolved") || result.equals("Closed"));
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
            assert false : "Stop passing null into getStatus()";
			return null;
		}
		
		log.info("Updating status for defect " + defect.getNativeId());
		
		String result = restUtils.getUrlAsString(getUrlWithRest() + "issue/" + defect.getNativeId(),
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

        assert false : "You should have a valid connection by this point.";
        return null;
	}
	
	@Override
	public String getTrackerError() {
		log.info("Attempting to find the reason that JIRA integration failed.");
		
		String reason;
		
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
		String returnString;
		
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
		String result = restUtils.postUrlAsString(getUrlWithRest() + "search", payload, getUsername(), getPassword(), CONTENT_TYPE);
		List<Defect> defectList = list();
		try {
            String issuesString = JsonUtils.getStringProperty(result, "issues");

            JSONArray returnArray = JsonUtils.getJSONArray(issuesString);

            if (returnArray != null) {
                for (int i = 0; i < returnArray.length(); i++) {
                    Defect defect = new Defect();
                    defect.setNativeId(returnArray.getJSONObject(i).getString("key"));
                    defectList.add(defect);
                }
            }
        } catch (JSONException e) {
            log.warn("JSON parsing failed when trying to get defect list.");
        }
					
		return defectList;
	}

}
