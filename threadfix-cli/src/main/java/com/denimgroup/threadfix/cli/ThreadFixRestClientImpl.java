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
package com.denimgroup.threadfix.cli;
public class ThreadFixRestClientImpl implements ThreadFixRestClient {
	
	private HttpRestUtils util = new HttpRestUtils();
	
	/**
	 * Default constructor that will read configuration from a local .properties file
	 */
	public ThreadFixRestClientImpl() {
		
	}
	
	/**
	 * Custom constructor for when you want to programmatically specify the ThreadFix URL and API key
	 * 
	 * @param url URL for the ThreadFix server
	 * @param apiKey API key to use when accessing the ThreadFix server
	 */
	public ThreadFixRestClientImpl(String url, String apiKey) {
		util.setDurable(false);
		util.setKey(apiKey);
		util.setUrl(url);
	}
	
	public String createApplication(String teamId, String name, String url) {
		String result = util.httpPost(util.getUrl() + "/teams/" + teamId + "/applications/new",
				new String[] {"apiKey",      "name", "url"},
				new String[] { util.getKey(), name,   url});
		
		return result;
	}
	
	public String setParameters(String appId, String frameworkType, String repositoryUrl) {
		String result = util.httpPost(util.getUrl() + "/applications/" + appId + "/setParameters",
				new String[] {"apiKey",      "frameworkType", "repositoryUrl"},
				new String[] { util.getKey(), frameworkType,   repositoryUrl});
		
		return result;
	}
	
	public String createTeam(String name) {
		String result = util.httpPost(util.getUrl() + "/teams/new",
				new String[] {"apiKey",      "name"},
				new String[] { util.getKey(), name});
		
		return result;
	}
	
	public String getRules(String wafId) {
		String result = util.httpGet(util.getUrl() + "/wafs/" + wafId + "/rules" +
				"?apiKey=" + util.getKey());
		
		return result;
	}

	public String searchForWafByName(String name) {
		String result = util.httpGet(util.getUrl() + "/wafs/lookup" +
				"?apiKey=" + util.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public String searchForWafById(String wafId) {
		String result = util.httpGet(util.getUrl() + "/wafs/" + wafId +
				"?apiKey=" + util.getKey());
		
		return result;
	}
	
	public String createWaf(String name, String type) {
		String result = util.httpPost(util.getUrl() + "/wafs/new",
				new String[] {"apiKey",      "name", "type"},
				new String[] { util.getKey(), name,   type});
		
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
		String result = util.httpGet(util.getUrl() + "/teams/?apiKey=" + util.getKey());
		return result;
	}
	
	public String searchForApplicationById(String id) {
		String result = util.httpGet(util.getUrl() + "/applications/" + id +
				"?apiKey=" + util.getKey());
		
		return result;
	}

	public String searchForApplicationByName(String name, String teamName) {
		String result = util.httpGet(util.getUrl() + "/applications/" + teamName + "/lookup" +
				"?apiKey=" + util.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public String searchForTeamById(String id) {
		String result = util.httpGet(util.getUrl() + "/teams/" + id +
				"?apiKey=" + util.getKey());
		
		return result;
	}
	
	public String searchForTeamByName(String name) {
		String result = util.httpGet(util.getUrl() + "/teams/lookup" +
				"?apiKey=" + util.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public void setKey(String key) {
		util.setKey(key);
	}

	public void setUrl(String url) {
		util.setUrl(url);
	}
	
	public void setMemoryKey(String key) {
		util.setMemoryKey(key);
	}
	
	public void setMemoryUrl(String url) {
		util.setMemoryUrl(url);
	}
	
	public String uploadScan(String applicationId, String filePath) {
		String result = util.httpPostFile(util.getUrl() + "/applications/" + applicationId + "/upload",
				filePath,
				new String[] { "apiKey"       },
				new String[] {  util.getKey() });
		return result;
	}
	
	public String queueScan(String applicationId, String scannerType) {
		String result = util.httpPost(util.getUrl() + "/tasks/queueScan",
				new String[] { "apiKey",       "applicationId",		"scannerType" },
				new String[] {  util.getKey(), applicationId, scannerType });
		return result;
	}

	public String addAppUrl(String appId, String url) {
		String result = util.httpPost(util.getUrl() + "/applications/" + appId + "/addUrl",
				new String[] { "apiKey",       "url" },
				new String[] {  util.getKey(),  url});
		return result;
	}
	
	public String requestTask(String scanners, String agentConfig) {
		String result = util.httpPost(util.getUrl() + "/tasks/requestTask",
				new String[] { "apiKey",			"scanners",		"agentConfig" },
				new String[] { util.getKey(), 		scanners,		agentConfig });
		return result;
	}
	
	/**
	 * Determine if we want to pass the taskId as a parameter or if we want to REST it up
	 * @param scanQueueTaskId
	 * @param message
	 * @return
	 */
	public String taskStatusUpdate(String scanQueueTaskId, String message) {
		String result = util.httpPost(util.getUrl() + "/tasks/taskStatusUpdate",
				new String[] { "apiKey",		"scanQueueTaskId",	"message" },
				new String[] { util.getKey(),	scanQueueTaskId,	message });
		return result;
	}
	
	public String setTaskConfig(String appId, String scannerType, String filePath) {
		String url = util.getUrl() + "/tasks/setTaskConfig";
		String[] paramNames 	= { "apiKey",		"appId", 	"scannerType" };
		String[] paramValues 	= {  util.getKey(),	appId,		scannerType };
		String result = util.httpPostFile(url, filePath, paramNames, paramValues );
		return result;
	}
	
	/**
	 * TODO - Determine if we want to pass the scanQueueTaskId as a parameter or if we want to REST it up
	 * @param filePath
	 * @param secureTaskKey
	 * @return
	 */
	public String completeTask(String scanQueueTaskId, String filePath, String secureTaskKey) {
		String url = util.getUrl() + "/tasks/completeTask";
		String[] paramNames 	= { "apiKey",		"scanQueueTaskId", "secureTaskKey" };
		String[] paramValues 	= {  util.getKey(),	scanQueueTaskId,   secureTaskKey };
		String result = util.httpPostFile(url, filePath, paramNames, paramValues );
		return result;
	}
	
	public String failTask(String scanQueueTaskId, String message, String secureTaskKey) {
		String result = util.httpPost(util.getUrl() + "/tasks/failTask",
				new String[] { "apiKey",		"scanQueueTaskId",	"message", "secureTaskKey" },
				new String[] { util.getKey(),	scanQueueTaskId,	message,    secureTaskKey });
		return result;
	}

	public String addDynamicFinding(String applicationId, String vulnType, String severity,
		String nativeId, String parameter, String longDescription,
		String fullUrl, String path) {
		String result = util.httpPost(util.getUrl() + "/applications/" + applicationId +
					"/addFinding",
				new String[] { "apiKey", "vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"fullUrl", "path" },
				new String[] {  util.getKey(), vulnType, severity,
								nativeId, parameter, longDescription,
								fullUrl, path });
		return result;
	}
	
	public String addStaticFinding(String applicationId, String vulnType, String severity,
			String nativeId, String parameter, String longDescription,
			String filePath, String column, String lineText, String lineNumber) {
		String result = util.httpPost(util.getUrl() + "/applications/" + applicationId +
				"/addFinding",
				new String[] { "apiKey", "vulnType", "severity",
								"nativeId", "parameter", "longDescription",
								"filePath", "column", "lineText", "lineNumber"},
				new String[] {  util.getKey(), vulnType, severity,
								nativeId, parameter, longDescription,
								filePath, column, lineText, lineNumber });
		return result;
	}

}
