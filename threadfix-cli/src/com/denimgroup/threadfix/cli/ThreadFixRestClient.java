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
	
	public String addApplicationChannel(String appId, String channelName) {
		String result = util.httpPost(util.getUrl() + "/teams/0/applications/" + appId + "/addChannel",
				new String[] { "apiKey",       "channelName" }, 
				new String[] {  util.getKey(), channelName });
		return result;
	}
	
	public String createApplication(String teamId, String name, String url) {
		String result = util.httpPost(util.getUrl() + "/teams/" + teamId + "/applications/new",
				new String[] {"apiKey",      "name", "url"},
				new String[] { util.getKey(), name,   url});
		
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
	
	public String getAllTeams() {
		String result = util.httpGet(util.getUrl() + "/teams/?apiKey=" + util.getKey());
		return result;
	}
	
	public String searchForApplicationById(String id) {
		String result = util.httpGet(util.getUrl() + "/teams/0/applications/" + id +
				"?apiKey=" + util.getKey());
		
		return result;
	}

	public String searchForApplicationByName(String name) {
		String result = util.httpGet(util.getUrl() + "/teams/0/applications/lookup" +
				"?apiKey=" + util.getKey() +
				"&name=" + name);
		
		return result;
	}
	
	public String searchForApplicationChannel(String appId, String channelName) {
		String result = util.httpGet(util.getUrl() + "/teams/0/applications/" + appId + "/lookupChannel" +
				"?apiKey=" + util.getKey() +
				"&channelName=" + channelName);
		
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

	public String uploadScan(String applicationChannelId, String filePath) {
		String result = util.httpPostFile(util.getUrl() + "/teams/0/applications/4/upload", 
				filePath,
				new String[] { "apiKey",       "channelId" },
				new String[] {  util.getKey(), applicationChannelId });
		return result;
	}
	
	public String queueScan(String applicationId, String scannerType) {
		String result = util.httpPost(util.getUrl() + "/tasks/queueScan",
				new String[] { "apiKey",       "applicationId",		"scannerType" },
				new String[] {  util.getKey(), applicationId, scannerType });
		return(result);
	}

}
