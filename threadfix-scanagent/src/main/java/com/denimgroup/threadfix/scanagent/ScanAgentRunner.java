package com.denimgroup.threadfix.scanagent;

import com.denimgroup.threadfix.data.entities.ScanQueueTask;
import com.denimgroup.threadfix.data.entities.Task;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.scanagent.configuration.OperatingSystem;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.scanners.AbstractScanAgent;
import com.denimgroup.threadfix.scanagent.scanners.ScanAgentFactory;
import com.denimgroup.threadfix.scanagent.util.ConfigurationInfo;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import com.denimgroup.threadfix.scanagent.util.ScanAgentPropertiesManager;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.List;

/**
 * TODO refactor out the configuration section
 */
public class ScanAgentRunner {

    private static Logger LOG = Logger.getLogger(ScanAgentRunner.class);

    private String agentConfig;

    private int pollIntervalInSeconds;
    private OperatingSystem operatingSystem;
    private List<Scanner> availableScanners;
    private String baseWorkDir;

    int numTasksAttempted = 0;
    private int maxTasks;

    private ThreadFixRestClient tfClient;

    public ScanAgentRunner() {
        // TODO refactor this
        this.tfClient = new ThreadFixRestClientImpl(new ScanAgentPropertiesManager());
        agentConfig = ConfigurationInfo.getAgentConfig();
    }

    // for testing
    public void setTfClient(ThreadFixRestClient client) {
        this.tfClient = client;
    }

    public void run() {
        readConfiguration();
        LOG.info("Scan agent configured");

        if (checkAndLogConfiguration()) {
            //	Main polling loop
            pollAndRunTasks();
        }

        LOG.info("Number of tasks run: " + numTasksAttempted);
    }

    private void pollAndRunTasks() {
        String lastErrorMessage = null;

        LOG.info("Configuration was OK, entering polling loop.");

        while (keepPolling()) {
            RestResponse<Task> taskResponse = requestTask();

            Task currentTask = null;

            if (taskResponse.success) {
                currentTask = taskResponse.object;
            }

            if (currentTask != null) {
                LOG.info("Got task from ThreadFix server.");
                doTask(currentTask);
                lastErrorMessage = null;
            } else {
                if (lastErrorMessage == null ||
                        !lastErrorMessage.equals(taskResponse.message)) {
                    LOG.info("Got first null task from requestTask(). Message: " +
                            taskResponse.message);
                    LOG.info("Switching to debug logging until something happens.");

                    lastErrorMessage = taskResponse.message;
                } else {
                    LOG.debug("Got another null task from requestTask.");
                }
            }

            try {
                Thread.sleep(pollIntervalInSeconds * 1000);
            } catch (InterruptedException e) {
                LOG.error("Got an InterruptedException while waiting until we check for our next task: " + e.getMessage(), e);
            }
        }
        LOG.info("Reached max number of tasks: " + this.numTasksAttempted + ". Shutting down");
    }

    private boolean keepPolling() {
        boolean retVal = true;

        if (this.maxTasks > 0) {
            retVal = this.numTasksAttempted < this.maxTasks;
        }

        return retVal;
    }

    @NotNull
    private static String makeScannerList(@NotNull List<Scanner> scanners) {
        StringBuilder sb = new StringBuilder();
        String prefix="";

        for(Scanner scanner : scanners) {
            sb.append(prefix).append(scanner.getName());
            prefix = ",";
        }

        return(sb.toString());
    }

    @NotNull
    private RestResponse<Task> requestTask() {
        LOG.debug("Requesting a new task");
        RestResponse<Task> retVal;

        String scannerList = makeScannerList(this.availableScanners);

        if (!scannerList.isEmpty()) {
            retVal = tfClient.requestTask(scannerList, agentConfig);
        } else {
            retVal = RestResponse.failure("No scanners were configured.");
        }

        return retVal;
    }

    private void doTask(@NotNull Task task) {
        this.numTasksAttempted++;

        try {
            LOG.info("Going to attempt task(" + this.numTasksAttempted + "): " + task);

            String taskType = task.getTaskType();
            AbstractScanAgent theAgent =
                    ScanAgentFactory.getScanAgent(getScanner(taskType), baseWorkDir);

            if (theAgent == null) {
                LOG.error("Failed to retrieve a scan agent implementation for " + taskType + ".");

            } else {

                //	TODO - Clean up the gross way we handle these callbacks
                theAgent.setCurrentTaskId(task.getTaskId());
                theAgent.setTfClient(tfClient);
                File taskResult = theAgent.doTask(task.getTaskConfig());
                if(taskResult != null) {
                    LOG.info("Task appears to have completed successfully: " + task);
                    LOG.info("Results from task should be located at: " + taskResult.getAbsolutePath());

                    LOG.debug("Attempting to complete task: " + task.getTaskId() +
                            " with file: " + taskResult.getAbsolutePath());

                    RestResponse<ScanQueueTask> result = tfClient.completeTask(
                            String.valueOf(task.getTaskId()),
                            taskResult.getAbsolutePath(),
                            task.getSecureTaskKey());

                    if (result.success) {
                        LOG.info("Successfully sent task completion update. Task status is now " +
                                result.object.getTaskStatus());
                    } else {
                        LOG.error("Failed to update server on task completion. Message: " + result.message);
                    }
                } else {
                    //	TODO - Look at better ways to get some sort of reason the scan wasn't successful
                    //	The only way we can report back right now is if an uncaught exception occurs which is
                    //	(hopefully) a pretty rare situation.
                    String message = "Task appears not to have completed successfully: " + task;
                    tfClient.failTask(String.valueOf(task.getTaskId()), message, task.getSecureTaskKey());
                    LOG.warn(message);
                }
            }

            LOG.info("Finished attempting task: " + task);
        } catch (Exception e) {
            String message = "Exception thrown while trying to run scan: " + e.getMessage();
            LOG.warn(message, e);
            tfClient.failTask(String.valueOf(task.getTaskId()), message, task.getSecureTaskKey());
        }

    }

    private void readConfiguration() {
        this.baseWorkDir           = ScanAgentPropertiesManager.getWorkingDirectory();
        this.pollIntervalInSeconds = ScanAgentPropertiesManager.getPollInterval();
        this.maxTasks              = ScanAgentPropertiesManager.getMaxTasks();

        this.operatingSystem = new OperatingSystem(System.getProperty("os.name"),
                System.getProperty("os.version"));

        this.availableScanners = ConfigurationUtils.readAllScanners();

        LOG.debug("scanagent.pollInterval=" + this.pollIntervalInSeconds);
        LOG.debug("scanagent.maxTasks=" + this.maxTasks);
    }

    private boolean checkAndLogConfiguration() {
        LOG.info("GenericScanAgent configuration:");
        if(operatingSystem != null) {
            LOG.info(this.operatingSystem);
        } else {
            LOG.info("No operating system configured (NULL)");
        }
        int i = 0;
        if(availableScanners != null) {
            if(availableScanners.size() == 0) {
                LOG.info("No scanners configured");
                return false;
            } else {
                LOG.info("Scanners:");
                for(Scanner s : availableScanners) {
                    LOG.info("[" + i + "]" + s);
                    i++;
                }
            }
        } else {
            LOG.info("No scanners configured (NULL)");
            return false;
        }
        return true;
    }

    @NotNull
    private Scanner getScanner(String scannerName){
        for (Scanner scan: availableScanners) {
            if (scan.getName().equalsIgnoreCase(scannerName))
                return scan;
        }
        return new Scanner();
    }
}
