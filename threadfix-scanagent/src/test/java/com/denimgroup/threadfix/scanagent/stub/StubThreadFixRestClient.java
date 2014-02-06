package com.denimgroup.threadfix.scanagent.stub;

import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
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
    public RestResponse<Application> createApplication(String teamId, String name, String url) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Application> setParameters(String appId, String frameworkType, String repositoryUrl) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Organization> createTeam(String name) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<String> getRules(String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Waf> searchForWafByName(String name) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Waf> searchForWafById(String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Waf> createWaf(String name, String type) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Application> addWaf(String appId, String wafId) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Organization[]> getAllTeams() {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Override
    public RestResponse<String> getAllTeamsPrettyPrint() {
        return null;
    }

    @Nullable
    @Override
    public RestResponse<Application> searchForApplicationById(String id) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Application> searchForApplicationByName(String name, String teamName) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Organization> searchForTeamById(String id) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Organization> searchForTeamByName(String name) {
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
    public RestResponse<Scan> uploadScan(String applicationId, String filePath) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<ScanQueueTask> queueScan(String applicationId, String scannerType) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Application> addAppUrl(String appId, String url) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Task> requestTask(String scanners, String agentConfig) {
        String retVal = null;
        if (this.url.equals(ScanAgentRunnerTests.RETURN_NULL_URL))
            return RestResponse.success(null);
        else if (this.url.equals(ScanAgentRunnerTests.RETURN_ERROR_URL))
            retVal = "errorResponse";
        else if (this.url.equals(ScanAgentRunnerTests.RETURN_GOOD_URL))
            retVal = "{\"secureTaskKey\":\"k9UDPUdTn0gYYet6emMxFoMWuB4w1WQz4JjPF4uuZuA\",\"taskConfig\":{\"configParams\":{}," +
                    "\"targetUrlString\":\"http://localhost:8086/bodgeit/\",\"dataBlobs\":{}," +
                    "\"targetUrl\":\"http://localhost:8086/bodgeit/\"},\"taskId\":2,\"taskType\":\"OWASP Zed Attack Proxy\"}";
        return RestResponse.failure(retVal);
    }

    @Nullable
    @Override
    public RestResponse<String> taskStatusUpdate(String scanQueueTaskId, String message) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<String> setTaskConfig(String appId, String scannerType, String filePath) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<ScanQueueTask> completeTask(String scanQueueTaskId, String filePath, String secureTaskKey) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<String> failTask(String scanQueueTaskId, String message, String secureTaskKey) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Finding> addDynamicFinding(String applicationId, String vulnType, String severity, String nativeId, String parameter, String longDescription, String fullUrl, String path) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }

    @Nullable
    @Override
    public RestResponse<Finding> addStaticFinding(String applicationId, String vulnType, String severity, String nativeId, String parameter, String longDescription, String filePath, String column, String lineText, String lineNumber) {
        return null;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
