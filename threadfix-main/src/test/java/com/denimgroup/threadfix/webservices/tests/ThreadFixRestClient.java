package com.denimgroup.threadfix.webservices.tests;

public class ThreadFixRestClient {
	
	HttpRestUtils util = new HttpRestUtils();
	
	public String addApplicationChannel(String appId, String channelName) {
		String result = util.httpPost(util.getUrl() + "/teams/0/applications/" + appId + "/addChannel",
				new String[] { "apiKey",      "channelName" }, 
				new String[] {  util.getKey(), channelName });
		return result;
	}
	
	public String addWaf(String appId, String wafId) {
		String result = util.httpPost(util.getUrl() + "/teams/0/applications/"
					+ appId + "/setWaf", 
				new String[] { "apiKey",     "wafId" }, 
				new String[] { util.getKey(), wafId });
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
	
	public String createWaf(String name, String type) {
		String result = util.httpPost(util.getUrl() + "/wafs/new",
				new String[] {"apiKey",      "name", "type"},
				new String[] { util.getKey(), name,   type});
		
		return result;
	}
	
	public String getRules(String wafId) {
		String result = util.httpGet(util.getUrl() + "/wafs/" + wafId + "/rules" +
				"?apiKey=" + util.getKey());
		
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
	
	public String searchForWafById(String wafId) {
		String result = util.httpGet(util.getUrl() + "/wafs/" + wafId +
				"?apiKey=" + util.getKey());
		
		return result;
	}

	public String searchForWafByName(String name) {
		String result = util.httpGet(util.getUrl() + "/wafs/lookup" +
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

	// TODO remove the 0 and 4 in the URL.
	// Doesn't matter now but the numbers are not right.
	public String uploadScan(String applicationChannelId, String filePath) {
		String result = util.httpPostFile(util.getUrl() + "/teams/0/applications/4/upload", 
				filePath,
				new String[] { "apiKey",       "channelId" },
				new String[] {  util.getKey(), applicationChannelId });
		return result;
	}
	
	public String addDynamicFinding(String applicationId, String vulnType, String severity, 
			String nativeId, String parameter, String longDescription,
			String fullUrl, String path) {
		String result = util.httpPost(util.getUrl() + "/teams/0/applications/" + applicationId +
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
		String result = util.httpPost(util.getUrl() + "/teams/0/applications/" + applicationId +
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
