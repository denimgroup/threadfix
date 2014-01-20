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
package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.properties.PropertiesManager;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class ThreadFixRestClientImpl implements ThreadFixRestClient {
	
	private PropertiesManager manager = PropertiesManager.getInstance();

	/**
	 * Default constructor that will read configuration from a local .properties file
	 */
	public ThreadFixRestClientImpl() {
		
	}
	
	/**
	 * Custom constructor for when you want to use the in-memory properties
	 * 
	 * @param url URL for the ThreadFix server
	 * @param apiKey API key to use when accessing the ThreadFix server
	 */
	public ThreadFixRestClientImpl(String url, String apiKey) {
        setMemoryKey(apiKey);
        setMemoryUrl(url);
	}
	
	public String createApplication(String teamId, String name, String url) {
        return HttpRestUtils.httpPost(manager.getUrl() + "/teams/" + teamId + "/applications/new",
                new String[] {"apiKey",      "name", "url"},
                new String[] { manager.getKey(), name,   url});
	}
	
	public String setParameters(String appId, String frameworkType, String repositoryUrl) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/applications/" + appId + "/setParameters",
				new String[] {"apiKey",      "frameworkType", "repositoryUrl"},
				new String[] { manager.getKey(), frameworkType,   repositoryUrl});
		
		return result;
	}
	
	public String createTeam(String name) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/teams/new",
				new String[] {"apiKey",      "name"},
				new String[] { manager.getKey(), name});
		
		return result;
	}
	
	public String getRules(String wafId) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/wafs/" + wafId + "/rules" +
				"?apiKey=" + manager.getKey());
		
		return result;
	}

	public String searchForWafByName(String name) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/wafs/lookup" +
				"?apiKey=" + manager.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public String searchForWafById(String wafId) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/wafs/" + wafId +
				"?apiKey=" + manager.getKey());
		
		return result;
	}
	
	public String createWaf(String name, String type) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/wafs/new",
				new String[] {"apiKey",      "name", "type"},
				new String[] { manager.getKey(), name,   type});
		
		return result;
	}
	
	/**
	 * TODO - Actually implement this method.
	 * 
	 * @param appId
	 * @param wafId
	 * @return
	 */
	public String addWaf(String appId, String wafId) {
		// TODO Auto-generated method stub
		return null;
	}

	public String getAllTeams() {
		return HttpRestUtils.httpGet(manager.getUrl() + "/teams/?apiKey=" + manager.getKey());
	}
    
    public String getAllTeamsPrettyPrint() {
        final String result = HttpRestUtils.httpGet(manager.getUrl() + "/teams/?apiKey=" + manager.getKey());

        final ObjectMapper objectMapper = new ObjectMapper();

        final List<Map<String, Object>> teamsData;

        try {
            teamsData = objectMapper.readValue(result, new TypeReference<List<Map<String, Object>>>() {});
        } catch (final IOException e) {
            e.printStackTrace();
            return "There was an error parsing JSON response.";
        }

        if (teamsData.isEmpty()) {
            return "These aren't the droids you're looking for.";
        } else {
            final StringBuilder outputBuilder = new StringBuilder();

            for (final Map<String, Object> teamData : teamsData) {
                final Boolean teamActive = (Boolean) teamData.get("active");
                @SuppressWarnings("unchecked")
                final List<Map<String, Object>> applications = (List<Map<String, Object>>) teamData.get("applications");

                if (teamActive && !applications.isEmpty()) {
                    final String teamName = (String) teamData.get("name");

                    for (final Map<String, Object> application : applications) {
                        final Boolean applicationActive = (Boolean) application.get("active");

                        if (applicationActive) {
                            final String applicationName = (String) application.get("name");
                            final Integer id = (Integer) application.get("id");

                            outputBuilder.append(teamName);
                            outputBuilder.append(";");
                            outputBuilder.append(applicationName);
                            outputBuilder.append(";");
                            outputBuilder.append(id);
                            outputBuilder.append("\n");
                        }
                    }
                }
            }

            outputBuilder.setLength(outputBuilder.length() - 1);
            return outputBuilder.toString();
        }
    }	

	public String searchForApplicationById(String id) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/applications/" + id +
				"?apiKey=" + manager.getKey());
		
		return result;
	}

	public String searchForApplicationByName(String name, String teamName) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/applications/" + teamName + "/lookup" +
				"?apiKey=" + manager.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public String searchForTeamById(String id) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/teams/" + id +
				"?apiKey=" + manager.getKey());
		
		return result;
	}
	
	public String searchForTeamByName(String name) {
		String result = HttpRestUtils.httpGet(manager.getUrl() + "/teams/lookup" +
				"?apiKey=" + manager.getKey() +
				"&name=" + name);

        return result;
    }
	
	public void setKey(String key) {
		manager.setKey(key);
	}

	public void setUrl(String url) {
        manager.setUrl(url);
	}
	
	public void setMemoryKey(String key) {
        manager.setMemoryKey(key);
	}
	
	public void setMemoryUrl(String url) {
        manager.setMemoryUrl(url);
	}
	
	public String uploadScan(String applicationId, String filePath) {
		String result = HttpRestUtils.httpPostFile(manager.getUrl() + "/applications/" + applicationId + "/upload",
                filePath,
                new String[]{"apiKey"},
                new String[]{manager.getKey()});
		return result;
	}
	
	public String queueScan(String applicationId, String scannerType) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/tasks/queueScan",
				new String[] { "apiKey",       "applicationId",		"scannerType" },
				new String[] {  manager.getKey(), applicationId, scannerType });
		return result;
	}

	public String addAppUrl(String appId, String url) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/applications/" + appId + "/addUrl",
				new String[] { "apiKey",       "url" },
				new String[] {  manager.getKey(),  url});
		return result;
	}
	
	public String requestTask(String scanners, String agentConfig) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/tasks/requestTask",
				new String[] { "apiKey",			"scanners",		"agentConfig" },
				new String[] { manager.getKey(), 		scanners,		agentConfig });
		return result;
	}
	
	/**
	 * Determine if we want to pass the taskId as a parameter or if we want to REST it up
	 * @param scanQueueTaskId
	 * @param message
	 * @return
	 */
	public String taskStatusUpdate(String scanQueueTaskId, String message) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/tasks/taskStatusUpdate",
                new String[]{"apiKey", "scanQueueTaskId", "message"},
                new String[]{manager.getKey(), scanQueueTaskId, message});
		return result;
	}
	
	public String setTaskConfig(String appId, String scannerType, String filePath) {
		String url = manager.getUrl() + "/tasks/setTaskConfig";
		String[] paramNames 	= { "apiKey",		"appId", 	"scannerType" };
		String[] paramValues 	= {  manager.getKey(),	appId,		scannerType };
		String result = HttpRestUtils.httpPostFile(url, filePath, paramNames, paramValues );
		return result;
	}
	
	/**
	 * TODO - Determine if we want to pass the scanQueueTaskId as a parameter or if we want to REST it up
	 * @param filePath
	 * @param secureTaskKey
	 * @return
	 */
	public String completeTask(String scanQueueTaskId, String filePath, String secureTaskKey) {
		String url = manager.getUrl() + "/tasks/completeTask";
		String[] paramNames 	= { "apiKey",		"scanQueueTaskId", "secureTaskKey" };
		String[] paramValues 	= {  manager.getKey(),	scanQueueTaskId,   secureTaskKey };
		String result = HttpRestUtils.httpPostFile(url, filePath, paramNames, paramValues);
        return result;
	}
	
	public String failTask(String scanQueueTaskId, String message, String secureTaskKey) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/tasks/failTask",
				new String[] { "apiKey",		"scanQueueTaskId",	"message", "secureTaskKey" },
				new String[] { manager.getKey(),	scanQueueTaskId,	message,    secureTaskKey });
        return result;
	}

	public String addDynamicFinding(String applicationId, String vulnType, String severity,
		String nativeId, String parameter, String longDescription,
		String fullUrl, String path) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/applications/" + applicationId +
					"/addFinding",
				new String[] { "apiKey", "vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"fullUrl", "path" },
				new String[] {  manager.getKey(), vulnType, severity,
								nativeId, parameter, longDescription,
								fullUrl, path });
        return result;
	}
	
	public String addStaticFinding(String applicationId, String vulnType, String severity,
			String nativeId, String parameter, String longDescription,
			String filePath, String column, String lineText, String lineNumber) {
		String result = HttpRestUtils.httpPost(manager.getUrl() + "/applications/" + applicationId +
				"/addFinding",
				new String[] { "apiKey", "vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"filePath", "column", "lineText", "lineNumber"},
				new String[] {  manager.getKey(), vulnType, severity,
								nativeId, parameter, longDescription,
								filePath, column, lineText, lineNumber });
		return result;
	}

}
