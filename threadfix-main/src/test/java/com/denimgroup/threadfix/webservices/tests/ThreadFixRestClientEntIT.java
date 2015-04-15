package com.denimgroup.threadfix.webservices.tests;

import com.denimgroup.threadfix.WebServiceTests;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.Task;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@Category(WebServiceTests.class)
public class ThreadFixRestClientEntIT {
    String dummyUrl = "http://test.com";

    private ThreadFixRestClient getClient() {
        return new ThreadFixRestClientImpl(new TestUtils());
    }

    private RestResponse<Organization> createTeam(String name) {
        return getClient().createTeam(name);
    }

    private Integer getTeamId(String name) {
        RestResponse<Organization> teamResponse = createTeam(name);

        assertTrue("Rest Response was a failure. message was: " + teamResponse.message,
                teamResponse.success);
        assertNotNull("The returned team object was null.", teamResponse.object);

        return teamResponse.object.getId();
    }

    private RestResponse<Application> createApplication(String teamId, String name, String url) {
        return getClient().createApplication(teamId, name, url);
    }

    private Integer getApplicationId(String teamName, String name, String url) {
        RestResponse<Application> teamResponse = createApplication(
                getTeamId(teamName).toString(), name, url);

        assertTrue("Rest Response was a failure. message was: " + teamResponse.message,
                teamResponse.success);
        assertNotNull("The returned application object was null.", teamResponse.object);

        return teamResponse.object.getId();
    }

    @Test
    public void testQueueScan() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        RestResponse<ScanQueueTask> queueResponse = getClient().queueScan(appId, "Acunetix WVS");

        assertTrue("Future scan should have been queued.", queueResponse.success);
    }

    @Test
    public void testRequestTask() {
        String scannerList = "Acunetix WVS";
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        RestResponse<ScanQueueTask> queueResponse = getClient().queueScan(appId, "Acunetix WVS");

        RestResponse<Task> response = getClient().requestTask(scannerList, "");

        assertTrue(response != null && response.object != null);
    }

    @Test
    public void testTaskStatusUpdate() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        RestResponse<ScanQueueTask> queueResponse = getClient().queueScan(appId, "Acunetix WVS");

        String taskId = queueResponse.object.getId().toString();

        RestResponse<String> statusResponse = getClient().taskStatusUpdate(taskId, "This is a test.");

        assertTrue("Status should have been changed.", statusResponse.success);
    }

    @Test
    public void testSetTaskConfig() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        RestResponse<ScanQueueTask> queueResponse = getClient().queueScan(appId, "Acunetix WVS");

        String taskId = queueResponse.object.getId().toString();

        RestResponse<String> setResponse = getClient().setTaskConfig(taskId, "Acunetix WVS", ScanContents.getScanFilePath());

        assertTrue("Configuration for the task should have been set.", setResponse.success);
    }

    @Test
    public void testCompleteTask() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        getClient().queueScan(appId, "Acunetix WVS");

        RestResponse<Task> requestTask = getClient().requestTask("Acunetix WVS", "Test");
        String taskId = Integer.toString(requestTask.object.getTaskId());
        String taskKey = requestTask.object.getSecureTaskKey();

        RestResponse<ScanQueueTask> completionResponse = getClient().completeTask(taskId, ScanContents.getScanFilePath(), taskKey);

        assertTrue("Task should be completed.", completionResponse.success);

    }

    @Test
    public void testFailTest() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();

        getClient().queueScan(appId, "Acunetix WVS");

        RestResponse<Task> requestTask = getClient().requestTask("Acunetix WVS", "Test");
        String taskId = Integer.toString(requestTask.object.getTaskId());
        String taskKey = requestTask.object.getSecureTaskKey();

        RestResponse<String> failureResponse = getClient().failTask(taskId, "Task Failed.", taskKey);

        assertTrue("Task should have failed.", failureResponse.success);
    }
}
