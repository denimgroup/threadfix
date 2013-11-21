package com.denimgroup.threadfix.scanagent;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.data.entities.Task;
import com.denimgroup.threadfix.scanagent.configuration.OperatingSystem;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.scanners.AbstractScanAgent;
import com.denimgroup.threadfix.scanagent.scanners.ScanAgentFactory;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import com.denimgroup.threadfix.scanagent.util.JsonUtils;
import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/19/13
 * Time: 4:35 PM
 * To change this template use File | Settings | File Templates.
 */
public class ScanAgentRunner {

    private static Logger log = Logger.getLogger(ScanAgentRunner.class);

    private String threadFixServerUrl;
    private String threadFixApiKey;
    private int pollIntervalInSeconds;
    private OperatingSystem operatingSystem;
    private List<Scanner> availableScanners;
    private String baseWorkDir;

    private int numTasksAttempted = 0;
    private int maxTasks;

    private String agentConfig;
    private ThreadFixRestClient tfClient;

    public ScanAgentRunner() {
        cacheAgentConfig();
    }

    public ThreadFixRestClient getTfClient() {
        return tfClient;
    }

    public void setTfClient(ThreadFixRestClient tfClient) {
        this.tfClient = tfClient;
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

        if (checkAndLogConfiguration())
            //	Main polling loop
            pollAndRunTasks();

        log.info("Number of tasks run: " + getNumTasksAttempted());
    }

    private void pollAndRunTasks() {

        while(keepPolling()) {
            Task currentTask = requestTask();
            doTask(currentTask);
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

    /**
     * Get some data about the local agent configuration to help identify this
     * agent to the server. This isn't intended to be a secure unique identifier,
     * but is instead intended to provide some debugging support. This is then
     * cached so it can be sent along with requests to the ThreadFix server.
     */
    private void cacheAgentConfig() {
        StringBuilder sb = new StringBuilder();

        String prefix;

        //	Grab some OS/user/Java environment properties
        sb.append(makeSystemPropertyString("os.arch"));
        sb.append(makeSystemPropertyString("os.name"));
        sb.append(makeSystemPropertyString("os.version"));
        sb.append(makeSystemPropertyString("user.name"));
        sb.append(makeSystemPropertyString("user.dir"));
        sb.append(makeSystemPropertyString("user.home"));
        sb.append(makeSystemPropertyString("java.home"));
        sb.append(makeSystemPropertyString("java.vendor"));
        sb.append(makeSystemPropertyString("java.version"));

        //	Pull some info about the network configuration of the scan agent
        Enumeration<NetworkInterface> nets = null;
        try {
            nets = NetworkInterface.getNetworkInterfaces();

            for (NetworkInterface netint : Collections.list(nets)) {
//	        	String interfaceName = netint.getDisplayName();
                sb.append("NETWORK:");
                sb.append(netint.getDisplayName());
                sb.append("=");

                prefix = "";
                for(java.net.InterfaceAddress address : netint.getInterfaceAddresses()) {
                    InetAddress inetAddress = address.getAddress();
                    sb.append(prefix);
                    sb.append(inetAddress.getHostAddress());
                    prefix = ",";
                }
                sb.append("\n");
            }
        } catch (SocketException e) {
            String message = "Problems checking network interfaces when trying to gather agent config: " + e.getMessage();
            log.warn(message, e);
            sb.append("\nERROR=");
            sb.append(message);
        }

        this.agentConfig = sb.toString();

        log.debug("About to dump agent config");
        log.debug(this.agentConfig);
    }

    /**
     * Grab a system property and return a string in the format:
     * key=value\n
     * (note the trailing newline)
     *
     * @param propertyName
     * @return
     */
    @NotNull
    private static String makeSystemPropertyString(@NotNull String propertyName) {
        return propertyName + "=" + System.getProperty(propertyName) + "\n";
    }

    /**
     *
     * @return
     */
    private String getAgentConfig() {
        return(this.agentConfig);
    }

    /**
     * TOFIX - Actually pull this from the ThreadFix server
     * @return
     */
    @Nullable
    private Task requestTask() {

        log.info("Requesting a new task");
        Task retVal = null;

        log.info("Returning new task");

        String scannerList = makeScannerList(this.availableScanners);
        if (scannerList == null || scannerList.isEmpty())
            return retVal;
        Object theReturn = getTfClient().requestTask(scannerList, this.getAgentConfig());
        if(theReturn == null) {
            log.warn("Got a null task back from the ThreadFix server.");
        } else {
            String sReturn = (String)theReturn;
            if(sReturn.length() == 0) {
                log.warn("Got an empty string back in lieu of a task from the ThreadFix server.");
            } else {
                log.debug("Here's what we got back from the ThreadFix server: '" + sReturn + "'");
                try {
                    retVal = JsonUtils.convertJsonStringToTask(sReturn);
                } catch (Exception e) {
                    log.warn("Was unable to convert from Json string to Task.");
                }
            }
        }

        return(retVal);
    }

    private void doTask(@Nullable Task theTask) {
        File taskResult = null;

        this.numTasksAttempted++;

        try {
            if(theTask == null) {
                log.warn("Task(" + this.numTasksAttempted + ") was null. Not going to do anything for now.");
            } else {
                log.info("Going to attempt task(" + this.numTasksAttempted + "): " + theTask);

                String taskType = theTask.getTaskType();
                AbstractScanAgent theAgent = ScanAgentFactory.getScanAgent(getScanner(taskType), this.baseWorkDir);
                //	TODO - Clean up the gross way we handle these callbacks
                theAgent.setCurrentTaskId(theTask.getTaskId());
                theAgent.setTfClient(getTfClient());
                taskResult = theAgent.doTask(theTask.getTaskConfig());
                if(taskResult != null) {
                    log.info("Task appears to have completed successfully: " + theTask);
                    log.info("Results from task should be located at: " + taskResult.getAbsolutePath());

                    log.debug("Attempting to complete task: " + theTask.getTaskId() + " with file: " + taskResult.getAbsolutePath());

                    String result = getTfClient().completeTask(String.valueOf(theTask.getTaskId()), taskResult.getAbsolutePath(), theTask.getSecureTaskKey());
                    log.info("Result of completion attempt was: " + result);
                } else {
                    //	TODO - Look at better ways to get some sort of reason the scan wasn't successful
                    //	The only way we can report back right now is if an uncaught exception occurs which is
                    //	(hopefully) a pretty rare situation.
                    String message = "Task appears not to have completed successfully: " + theTask;
                    tfClient.failTask(String.valueOf(theTask.getTaskId()), message, theTask.getSecureTaskKey());
                    log.warn(message);
                }

                log.info("Finished attempting task: " + theTask);
            }
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

        this.availableScanners = ConfigurationUtils.readAllScanner(config);
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
