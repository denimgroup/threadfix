package com.denimgroup.threadfix.scanagent.stub;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.scanagent.ScanAgentRunnerTests;
import org.jetbrains.annotations.Nullable;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/20/13
 * Time: 11:21 AM
 * To change this template use File | Settings | File Templates.
 */
public class StubThreadFixRestClient implements ThreadFixRestClient {

    private String url;

    @Nullable
    @Override
    public String createApplication(String teamId, String name, String url) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String setParameters(String appId, String frameworkType, String repositoryUrl) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String createTeam(String name) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String getRules(String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForWafByName(String name) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForWafById(String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String createWaf(String name, String type) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String addWaf(String appId, String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String getAllTeams() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForApplicationById(String id) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForApplicationByName(String name, String teamName) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForTeamById(String id) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String searchForTeamByName(String name) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void setKey(String key) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void setUrl(String url) {
        this.url = url;
    }

    @Override
    public void setMemoryKey(String key) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public void setMemoryUrl(String url) {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String uploadScan(String applicationId, String filePath) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String queueScan(String applicationId, String scannerType) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String addAppUrl(String appId, String url) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String requestTask(String scanners, String agentConfig) {
        String retVal = null;
        if (this.url.equals(ScanAgentRunnerTests.RETURN_NULL_URL))
            return retVal;
        else if (this.url.equals(ScanAgentRunnerTests.RETURN_ERROR_URL))
            retVal = "errorResponse";
        else if (this.url.equals(ScanAgentRunnerTests.RETURN_GOOD_URL))
            retVal = "{\"secureTaskKey\":\"k9UDPUdTn0gYYet6emMxFoMWuB4w1WQz4JjPF4uuZuA\",\"taskConfig\":{\"configParams\":{}," +
                    "\"targetUrlString\":\"http://localhost:8086/bodgeit/\",\"dataBlobs\":{}," +
                    "\"targetUrl\":\"http://localhost:8086/bodgeit/\"},\"taskId\":2,\"taskType\":\"OWASP Zed Attack Proxy\"}";
        return retVal;
    }

    @Nullable
    @Override
    public String taskStatusUpdate(String scanQueueTaskId, String message) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String setTaskConfig(String appId, String scannerType, String filePath) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String completeTask(String scanQueueTaskId, String filePath, String secureTaskKey) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String failTask(String scanQueueTaskId, String message, String secureTaskKey) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String addDynamicFinding(String applicationId, String vulnType, String severity, String nativeId, String parameter, String longDescription, String fullUrl, String path) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public String addStaticFinding(String applicationId, String vulnType, String severity, String nativeId, String parameter, String longDescription, String filePath, String column, String lineText, String lineNumber) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
