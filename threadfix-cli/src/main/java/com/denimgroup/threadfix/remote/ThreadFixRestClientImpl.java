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

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.io.File;
import java.util.List;

public class ThreadFixRestClientImpl implements ThreadFixRestClient {

    final HttpRestUtils httpRestUtils;
    final PropertiesManager propertiesManager;

	/**
	 * Default constructor that will read configuration from a local .properties file
	 */
	public ThreadFixRestClientImpl() {
        propertiesManager = new PropertiesManager();
        httpRestUtils = new HttpRestUtils(propertiesManager);
	}

    public ThreadFixRestClientImpl(PropertiesManager manager) {
        propertiesManager = manager;
        httpRestUtils = new HttpRestUtils(propertiesManager);
    }
	
	/**
	 * Custom constructor for when you want to use the in-memory properties
	 * 
	 * @param url URL for the ThreadFix server
	 * @param apiKey API key to use when accessing the ThreadFix server
	 */
	public ThreadFixRestClientImpl(String url, String apiKey) {
        propertiesManager = new PropertiesManager();
        propertiesManager.setMemoryKey(apiKey);
        propertiesManager.setMemoryUrl(url);
        httpRestUtils = new HttpRestUtils(propertiesManager);
	}
	
	public RestResponse<Application> createApplication(String teamId, String name, String url) {
        return httpRestUtils.httpPost("/teams/" + teamId + "/applications/new",
                new String[] { "name", "url"},
                new String[] {  name,   url},
                Application.class);
	}
	
	public RestResponse<Application> setParameters(String appId, String frameworkType, String repositoryUrl) {
		return httpRestUtils.httpPost("/applications/" + appId + "/setParameters",
				new String[] {"frameworkType", "repositoryUrl"},
				new String[] { frameworkType,   repositoryUrl},
                Application.class);
	}
	
	public RestResponse<Organization> createTeam(String name) {
		return httpRestUtils.httpPost("/teams/new",
				new String[] {"name"},
				new String[] { name },
                Organization.class);
	}
	
	public RestResponse<String> getRules(String wafId) {
		return httpRestUtils.httpGet("/wafs/" + wafId + "/rules", String.class);
	}

	public RestResponse<Waf> searchForWafByName(String name) {
		return httpRestUtils.httpGet("/wafs/lookup", "&name=" + name, Waf.class);
	}
	
	public RestResponse<Waf> searchForWafById(String wafId) {
		return httpRestUtils.httpGet("/wafs/" + wafId, Waf.class);
	}
	
	public RestResponse<Waf> createWaf(String name, String type) {
		return httpRestUtils.httpPost("/wafs/new",
				new String[] {"name", "type"},
				new String[] { name,   type},
                Waf.class);
	}
	
	/**
	 *
     * @param appId
     * @param wafId
     * @return
	 */
	public RestResponse<Application> addWaf(String appId, String wafId) {
        return httpRestUtils.httpPost("/applications/" + appId + "/setWaf",
                new String[]{"wafId"},
                new String[]{wafId},
                Application.class);
	}

	public RestResponse<Organization[]> getAllTeams() {
		return httpRestUtils.httpGet("/teams/", Organization[].class);
	}
    
    public RestResponse<String> getAllTeamsPrettyPrint() {
        final RestResponse<Organization[]> teams = getAllTeams();

        if (teams.success && teams.object.length > 0) {
            StringBuilder outputBuilder = new StringBuilder();

            for (Organization team : teams.object) {
                List<Application> applications = team.getApplications();

                if (team.isActive() && !applications.isEmpty()) {
                    String teamName = team.getName();

                    for (Application application : applications) {
                        boolean applicationActive = application.isActive();

                        if (applicationActive) {
                            String applicationName = application.getName();
                            Integer id = application.getId();

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
            return RestResponse.success(outputBuilder.toString());
        } else {
            return RestResponse.failure("No Teams found.");
        }
    }	

	public RestResponse<Application> searchForApplicationById(String id) {
		return httpRestUtils.httpGet("/applications/" + id, Application.class);
	}

	public RestResponse<Application> searchForApplicationByName(String name, String teamName) {
		return httpRestUtils.httpGet("/applications/" + teamName + "/lookup",
				"&name=" + name, Application.class);
	}
	
	public RestResponse<Organization> searchForTeamById(String id) {
		return httpRestUtils.httpGet("/teams/" + id, Organization.class);
	}
	
	public RestResponse<Organization> searchForTeamByName(String name) {
		return httpRestUtils.httpGet("/teams/lookup", "&name=" + name, Organization.class);
    }
	
	public void setKey(String key) {
        propertiesManager.setKey(key);
	}

	public void setUrl(String url) {
        propertiesManager.setUrl(url);
	}
	
	public void setMemoryKey(String key) {
        propertiesManager.setMemoryKey(key);
	}
	
	public void setMemoryUrl(String url) {
        propertiesManager.setMemoryUrl(url);
	}
	
	public RestResponse<Scan> uploadScan(String applicationId, String filePath) {
		return httpRestUtils.httpPostFile("/applications/" + applicationId + "/upload",
                new File(filePath), new String[]{}, new String[]{}, Scan.class);
	}
	
	public RestResponse<ScanQueueTask> queueScan(String applicationId, String scannerType) {
		return httpRestUtils.httpPost("/tasks/queueScan",
				new String[] { "applicationId", "scannerType" },
				new String[] { applicationId, scannerType },
                ScanQueueTask.class);
	}

	public RestResponse<Application> addAppUrl(String appId, String url) {
		return httpRestUtils.httpPost("/applications/" + appId + "/addUrl",
				new String[] {"url"},
				new String[] { url },
                Application.class);
	}
	
	public RestResponse<Task> requestTask(String scanners, String agentConfig) {
		return httpRestUtils.httpPost("/tasks/requestTask",
				new String[] {"scanners", "agentConfig" },
				new String[] { scanners, agentConfig }, Task.class);
	}
	
	/**
	 * Determine if we want to pass the taskId as a parameter or if we want to REST it up
	 * @param scanQueueTaskId
	 * @param message
	 * @return
	 */
	public RestResponse<String> taskStatusUpdate(String scanQueueTaskId, String message) {
		return httpRestUtils.httpPost("/tasks/taskStatusUpdate",
                new String[]{"scanQueueTaskId", "message"},
                new String[]{ scanQueueTaskId, message}, String.class);
	}
	
	public RestResponse<String> setTaskConfig(String appId, String scannerType, String filePath) {
		String url = "/tasks/setTaskConfig";
		String[] paramNames 	= {	"appId", "scannerType" };
		String[] paramValues 	= { appId, scannerType };
		return httpRestUtils.httpPostFile(url, new File(filePath), paramNames, paramValues, String.class);
	}
	
	public RestResponse<ScanQueueTask> completeTask(String scanQueueTaskId, String filePath, String secureTaskKey) {
		String url = "/tasks/completeTask";
		String[] paramNames 	= {	"scanQueueTaskId", "secureTaskKey" };
		String[] paramValues 	= {  scanQueueTaskId,   secureTaskKey };
	    return httpRestUtils.httpPostFile(url, new File(filePath), paramNames, paramValues, ScanQueueTask.class);
	}
	
	public RestResponse<String> failTask(String scanQueueTaskId, String message, String secureTaskKey) {
		return httpRestUtils.httpPost("/tasks/failTask",
				new String[] {"scanQueueTaskId", "message", "secureTaskKey" },
				new String[] { scanQueueTaskId,	  message,   secureTaskKey }, String.class);
	}

	public RestResponse<Finding> addDynamicFinding(String applicationId, String vulnType, String severity,
		String nativeId, String parameter, String longDescription,
		String fullUrl, String path) {
		return httpRestUtils.httpPost("/applications/" + applicationId +
					"/addFinding",
				new String[] {"vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"fullUrl", "path" },
				new String[] {  vulnType, severity,
								nativeId, parameter, longDescription,
								fullUrl, path }, Finding.class);
	}
	
	public RestResponse<Finding> addStaticFinding(String applicationId, String vulnType, String severity,
			String nativeId, String parameter, String longDescription,
			String filePath, String column, String lineText, String lineNumber) {
		return httpRestUtils.httpPost("/applications/" + applicationId +
				"/addFinding",
				new String[] {"vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"filePath", "column", "lineText", "lineNumber"},
				new String[] {  vulnType, severity,
								nativeId, parameter, longDescription,
								filePath, column, lineText, lineNumber }, Finding.class);
	}

}
