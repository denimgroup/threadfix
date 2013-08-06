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

public class ThreadFixRestClient {
	
	HttpRestUtils util = new HttpRestUtils();
	
	public String createApplication(String teamId, String name, String url) {
		String result = util.httpPost(util.getUrl() + "/teams/" + teamId + "/applications/new",
				new String[] {"apiKey",      "name", "url"},
				new String[] { util.getKey(), name,   url});
		
		return result;
	}
	
	public String setParameters(String appId, String vulnTypeStrategy, 
			String sourceCodeAccessLevel, String frameworkType, String repositoryUrl) {
		String result = util.httpPost(util.getUrl() + "/applications/" + appId + "/setParameters",
				new String[] {"apiKey",      
					"vulnTypeStrategy", "sourceCodeAccessLevel", "frameworkType", "repositoryUrl"},
				new String[] { util.getKey(), 
					 vulnTypeStrategy,   sourceCodeAccessLevel,   frameworkType,   repositoryUrl});
		
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
		String result = util.httpGet(util.getUrl() + "/teams/" + teamName + "/applications/lookup" +
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
