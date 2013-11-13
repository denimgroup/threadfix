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

package com.denimgroup.threadfix.scanagent;

import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.Task;
import com.denimgroup.threadfix.scanagent.configuration.OperatingSystem;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import com.denimgroup.threadfix.scanagent.util.JsonUtils;

public final class ScanAgentRunner implements ServerConduit {

	public static final String SCAN_AGENT_VERSION = "2.0.0-DEVELOPMENT-1";
	
	static Logger log = Logger.getLogger(ScanAgentRunner.class);
	
	private String threadFixServerUrl;
	private String threadFixApiKey;
	private int pollIntervalInSeconds;
	private OperatingSystem operatingSystem;
	private List<Scanner> availableScanners;
	private String baseWorkDir;
	
	private int numTasksAttempted = 0;
	private int maxTasks;
	
	private String agentConfig;

	@SuppressWarnings("static-access")
	public static final Options getOptions() {
		Options options = new Options();
		
		options.addOption(new Option("help", "Print this message" ));
		options.addOption(new Option("printScannerOptions", "Prints available scanner type options"));
		
		Option runScanQueueTask = OptionBuilder.withLongOpt("runScanQueueTask")
				.withDescription("Request all scan queue tasks from ThreadFix server and execute them")
				.withLongOpt("run")
				.create("r");
		options.addOption(runScanQueueTask);
		
		Option set = OptionBuilder.withLongOpt("set")
				.withDescription("Set the ThreadFix base url, ThreadFix API key or Working directory properties")
				.create("s");
		options.addOption(set); 
		
		Option configureScan = OptionBuilder.withArgName("scannerType")
				.withValueSeparator(' ')
				.hasArgs(1)
				.withLongOpt("configureScan")
				.withDescription("Configure scan information")
				.create("cs");
		options.addOption(configureScan);				
		
		return options;
	}	
	
	/**
	 * @param args
	 */
	public static void main(String[] args) {

			Options options = getOptions();
			
			PosixParser parser = new PosixParser();
			try {
				CommandLine cmd = parser.parse( options, args);
				PropertiesConfiguration config = ConfigurationUtils.getPropertiesFile();
				if (config == null)
					return;
				config.setAutoSave(true);

				if (cmd.hasOption("help")) {
					HelpFormatter formatter = new HelpFormatter();
					formatter.printHelp("java -jar scanagent.jar", options );
					
				} else if (cmd.hasOption("s")) {
					
					ConfigurationUtils.configSystemInfo(config);
					
				} else if (cmd.hasOption("cs")) {
					String[] scanArgs = cmd.getOptionValues("cs");
					if (scanArgs.length != 1) {
						throw new ParseException("Wrong number of arguments.");
					}
					ScannerType scannerType = isValidScannerType(scanArgs[0]);
					if (scannerType != null) {
						ConfigurationUtils.configScannerType(scannerType, config);
					} else {
						println("Not correct scanner. See -printScannerOptions for details.");
					}

				} else if (cmd.hasOption("r")) {
					if (checkRequiredConfiguration(config))
						runScanQueue(config);

				} else if (cmd.hasOption("printScannerOptions")) {
					println("Available scanner type options:");
					for (ScannerType type : ScannerType.values()) {
						println("\t" + type.getShortName() + " (or " + type.getFullName() + ")");
					}
					
				} else {
					throw new ParseException("No arguments found.");
				}
				
			} catch (ParseException e) {
				if (e.getMessage() != null) {
					println(e.getMessage());
				}
				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp("java -jar scanagent.jar", options);
			} 		 
	}

	private static boolean checkRequiredConfiguration(
			PropertiesConfiguration config) {
		if (config.getString("scanagent.baseWorkDir","").isEmpty()) {
			System.out.println("Not found enough server configuration (ThreadFix URL, API Key or Working directory). " +
					"Please run '-s' to set up all of these information.");
			return false;
		}
		return true;
	}

	private static ScannerType isValidScannerType(String scanner) {
		return ScannerType.getScannerType(scanner);
	}

	private static void println(String string) {
		System.out.println(string);
	}	
	
	public static void runScanQueue(Configuration config) {
		
		log.info("Starting ThreadFix generic scan agent version " + SCAN_AGENT_VERSION);
		BasicConfigurator.configure();
		log.debug("Logging configured and running");
		log.info("Starting ThreadFix generic scan agent version " + SCAN_AGENT_VERSION);
		
		ScanAgentRunner myAgent = new ScanAgentRunner();
		myAgent.readConfiguration(config);
		log.info("Scan agent configured");
		
		int numTasksRun = 0;
		
		if (myAgent.checkAndLogConfiguration())
			//	Main polling loop
			numTasksRun = myAgent.pollAndRunTasks();
		
		log.info("Numbef of tasks run: " + numTasksRun);
		log.info("ThreadFix generic scan agent version " + SCAN_AGENT_VERSION + " stopping...");		
	}
	
	public ScanAgentRunner() {
		this.cacheAgentConfig();
	}
	
	public int pollAndRunTasks() {

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
		
		return(this.numTasksAttempted);
	}
	
	/**
	 * Send a message back to the server for the given task. This allows
	 * for server-side tracking and debugging - especially for long-running tasks.
	 */
	public void sendStatusUpdate(int taskId, String message) {
		log.debug("Sending server update for taskId: " + taskId + " of: " + message);
		ThreadFixRestClient tfClient = new ThreadFixRestClient(this.threadFixServerUrl, this.threadFixApiKey);
		String result = tfClient.taskStatusUpdate(String.valueOf(taskId), message);
		log.debug("Server response from task update was: " + result);
	}
	
	private boolean keepPolling() {
		boolean retVal;
		
		if(this.maxTasks > 0) {
			//	Only supposed to run for a limited number of times
			if(this.numTasksAttempted >= this.maxTasks) {
				//	We've reached the limit
				retVal = false;
			} else {
				//	Haven't reached the limit
				retVal = true;
			}
		} else {
			//	Supposed to run forever (default)
			retVal = true;
		}
		
		return(retVal);
	}
	
	private static String makeScannerList(List<Scanner> scanners) {
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
	private static String makeSystemPropertyString(String propertyName) {
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
	private Task requestTask() {
		
		log.info("Requesting a new task");
		Task retVal = null;
		
		log.info("Returning new task");
		
		ThreadFixRestClient tfClient = new ThreadFixRestClient(this.threadFixServerUrl, this.threadFixApiKey);
		String scannerList = makeScannerList(this.availableScanners);
		if (scannerList == null || scannerList.isEmpty()) 
			return retVal;
		Object theReturn = tfClient.requestTask(scannerList, this.getAgentConfig());
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
	
	private boolean doTask(Task theTask) {
		boolean retVal = false;
		File taskResult = null;
		ThreadFixRestClient tfClient = new ThreadFixRestClient(this.threadFixServerUrl, this.threadFixApiKey);
		
		this.numTasksAttempted++;
		
		try {			
			if(theTask == null) {
				log.warn("Task(" + this.numTasksAttempted + ") was null. Not going to do anything for now.");
			} else {
				log.info("Going to attempt task(" + this.numTasksAttempted + "): " + theTask);
				
				String taskType = theTask.getTaskType();
				AbstractScanAgent theAgent = ScanAgentFactory.getScanAgent(getScanner(taskType), this.baseWorkDir, this);
				//	TODO - Clean up the gross way we handle these callbacks
				theAgent.setCurrentTaskId(theTask.getTaskId());
				taskResult = theAgent.doTask(theTask.getTaskConfig());
				if(taskResult != null) {
					log.info("Task appears to have completed successfully: " + theTask);
					log.info("Results from task should be located at: " + taskResult.getAbsolutePath());
					
					log.debug("Attempting to complete task: " + theTask.getTaskId() + " with file: " + taskResult.getAbsolutePath());
					
					String result = tfClient.completeTask(String.valueOf(theTask.getTaskId()), taskResult.getAbsolutePath(), theTask.getSecureTaskKey());
					log.info("Result of completion attempt was: " + result);
					//	TOFIX - Determine if the result was successful or not. Currently returning true if we get to this point
					retVal = true;
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
		
		return(retVal);
	}

	private void readConfiguration(Configuration config) {

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
	
	private Scanner getScanner(String scannerName){
		for (Scanner scan: availableScanners) {
			if (scan.getName().equalsIgnoreCase(scannerName))
				return scan;
		}
		return new Scanner();
	}
}
