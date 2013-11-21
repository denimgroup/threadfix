package com.denimgroup.threadfix.cli;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/19/13
 * Time: 3:27 PM
 * To change this template use File | Settings | File Templates.
 */
public interface ThreadFixRestClient {

    public String createApplication(String teamId, String name, String url);
    public String setParameters(String appId, String frameworkType, String repositoryUrl);
    public String createTeam(String name);
    public String getRules(String wafId);
    public String searchForWafByName(String name);
    public String searchForWafById(String wafId);
    public String createWaf(String name, String type);
    public String addWaf(String appId, String wafId);
    public String getAllTeams();
    public String searchForApplicationById(String id);
    public String searchForApplicationByName(String name, String teamName);
    public String searchForTeamById(String id);
    public String searchForTeamByName(String name);
    public void setKey(String key);
    public void setUrl(String url);
    public void setMemoryKey(String key);
    public void setMemoryUrl(String url);
    public String uploadScan(String applicationId, String filePath);
    public String queueScan(String applicationId, String scannerType);
    public String addAppUrl(String appId, String url);
    public String requestTask(String scanners, String agentConfig);
    public String taskStatusUpdate(String scanQueueTaskId, String message);
    public String setTaskConfig(String appId, String scannerType, String filePath);
    public String completeTask(String scanQueueTaskId, String filePath, String secureTaskKey);
    public String failTask(String scanQueueTaskId, String message, String secureTaskKey);
    public String addDynamicFinding(String applicationId, String vulnType, String severity,
                                    String nativeId, String parameter, String longDescription,
                                    String fullUrl, String path);
    public String addStaticFinding(String applicationId, String vulnType, String severity,
                                   String nativeId, String parameter, String longDescription,
                                   String filePath, String column, String lineText, String lineNumber);
}
