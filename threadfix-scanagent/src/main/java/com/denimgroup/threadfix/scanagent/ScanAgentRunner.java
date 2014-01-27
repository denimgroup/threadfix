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
import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.List;

/**
 * TODO refactor out the configuration section
 */
public class ScanAgentRunner {

    private static Logger log = Logger.getLogger(ScanAgentRunner.class);

    private String threadFixServerUrl, threadFixApiKey, agentConfig;

    private int pollIntervalInSeconds;
    private OperatingSystem operatingSystem;
    private List<Scanner> availableScanners;
    private String baseWorkDir;

    private int numTasksAttempted = 0;
    private int maxTasks;

    private ThreadFixRestClient tfClient;

    public ScanAgentRunner() {
        // TODO refactor this
        this.tfClient = new ThreadFixRestClientImpl();
        agentConfig = ConfigurationInfo.getAgentConfig();
    }

    // for testing
    public void setTfClient(ThreadFixRestClient client) {
        this.tfClient = client;
    }

    public ThreadFixRestClient getTfClient() {
        return tfClient;
    }

    public int getNumTasksAttempted() {
        return numTasksAttempted;
    }

    public void run() {
        Configuration config = ConfigurationUtils.getPropertiesFile();
        readConfiguration(config);
        getTfClient().setUrl(this.threadFixServerUrl);
        getTfClient().setKey(this.threadFixApiKey);
        log.info("Scan agent configured");

        int numTasksRun = 0;

        if (checkAndLogConfiguration()) {
            //	Main polling loop
            pollAndRunTasks();
        }

        log.info("Number of tasks run: " + getNumTasksAttempted());
    }

    private void pollAndRunTasks() {

        while(keepPolling()) {
            Task currentTask = requestTask();
            if (currentTask != null) {
                doTask(currentTask);
            } else {
                log.info("Got null task from requestTask()");
            }

            try {
                Thread.sleep(pollIntervalInSeconds * 1000);
            } catch (InterruptedException e) {
                log.error("Got an InterruptedException while waiting until we check for our next task: " + e.getMessage(), e);
            }
        }
        log.info("Reached max number of tasks: " + this.numTasksAttempted + ". Shutting down");
    }

    private boolean keepPolling() {
        boolean retVal = true;

        if(this.maxTasks > 0) {
            //	Only supposed to run for a limited number of times
            if(this.numTasksAttempted >= this.maxTasks) {
                //	We've reached the limit
                retVal = false;
            } else {
                //	Haven't reached the limit
                retVal = true;
            }
        }

        return(retVal);
    }

    @NotNull
    private static String makeScannerList(@NotNull List<Scanner> scanners) {
        StringBuilder sb = new StringBuilder();
        String prefix="";

        for(Scanner scanner : scanners) {
            sb.append(prefix);
            sb.append(scanner.getName());
            prefix = ",";
        }

        return(sb.toString());
    }

    private String getAgentConfig() {
        return(this.agentConfig);
    }

    @Nullable
    private Task requestTask() {
        log.info("Requesting a new task");
        Task retVal = null;

        String scannerList = makeScannerList(this.availableScanners);

        if (!scannerList.isEmpty()) {

            RestResponse<Task> response = getTfClient().requestTask(scannerList, this.getAgentConfig());

            if (response.success) {
                retVal = response.object;
                log.info("Got Task successfully from server.");
            } else {
                log.error("Encountered error while requesting task: " + response.message);
            }
        }

        return retVal;
    }

    private void doTask(@NotNull Task theTask) {
        File taskResult = null;

        this.numTasksAttempted++;

        try {
            log.info("Going to attempt task(" + this.numTasksAttempted + "): " + theTask);

            String taskType = theTask.getTaskType();
            AbstractScanAgent theAgent = ScanAgentFactory.getScanAgent(getScanner(taskType), this.baseWorkDir);

            if (theAgent == null) {
                log.error("Failed to retrieve a scan agent implementation for " + taskType + ".");

            } else {

                //	TODO - Clean up the gross way we handle these callbacks
                theAgent.setCurrentTaskId(theTask.getTaskId());
                theAgent.setTfClient(getTfClient());
                taskResult = theAgent.doTask(theTask.getTaskConfig());
                if(taskResult != null) {
                    log.info("Task appears to have completed successfully: " + theTask);
                    log.info("Results from task should be located at: " + taskResult.getAbsolutePath());

                    log.debug("Attempting to complete task: " + theTask.getTaskId() +
                            " with file: " + taskResult.getAbsolutePath());

                    RestResponse<ScanQueueTask> result = getTfClient().completeTask(
                            String.valueOf(theTask.getTaskId()),
                            taskResult.getAbsolutePath(),
                            theTask.getSecureTaskKey());

                    if (result.success) {
                        log.info("Successfully sent task completion update. Task status is now " +
                                result.object.getTaskStatus());
                    } else {
                        log.error("Failed to update server on task completion. Message: " + result.message);
                    }
                } else {
                    //	TODO - Look at better ways to get some sort of reason the scan wasn't successful
                    //	The only way we can report back right now is if an uncaught exception occurs which is
                    //	(hopefully) a pretty rare situation.
                    String message = "Task appears not to have completed successfully: " + theTask;
                    tfClient.failTask(String.valueOf(theTask.getTaskId()), message, theTask.getSecureTaskKey());
                    log.warn(message);
                }
            }

            log.info("Finished attempting task: " + theTask);
        } catch (Exception e) {
            String message = "Exception thrown while trying to run scan: " + e.getMessage();
            log.warn(message, e);
            tfClient.failTask(String.valueOf(theTask.getTaskId()), message, theTask.getSecureTaskKey());
        }

    }

    private void readConfiguration(@NotNull Configuration config) {

        this.threadFixServerUrl = config.getString("scanagent.threadFixServerUrl");
        log.debug("scanagent.threadFixServerUrl=" + this.threadFixServerUrl);

        this.threadFixApiKey = config.getString("scanagent.threadFixApiKey");;
        this.baseWorkDir = config.getString("scanagent.baseWorkDir");;

        this.pollIntervalInSeconds = config.getInt("scanagent.pollInterval");
        log.debug("scanagent.pollInterval=" + this.pollIntervalInSeconds);

        this.maxTasks = config.getInt("scanagent.maxTasks");
        log.debug("scanagent.maxTasks=" + this.maxTasks);

        this.operatingSystem = new OperatingSystem(System.getProperty("os.name"), System.getProperty("os.version"));

        this.availableScanners = ConfigurationUtils.readAllScanner();
    }

    private boolean checkAndLogConfiguration() {
        log.info("GenericScanAgent configuration:");
        if(operatingSystem != null) {
            log.info(this.operatingSystem);
        } else {
            log.info("No operating system configured (NULL)");
        }
        int i = 0;
        if(availableScanners != null) {
            if(availableScanners.size() == 0) {
                log.info("No scanners configured");
                return false;
            } else {
                log.info("Scanners:");
                for(Scanner s : availableScanners) {
                    log.info("[" + i + "]" + s);
                    i++;
                }
            }
        } else {
            log.info("No scanners configured (NULL)");
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
