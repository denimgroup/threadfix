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

package com.denimgroup.threadfix.scanagent.scanners;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import com.denimgroup.threadfix.scanagent.util.ZipFileUtils;

public class ZapScanAgent extends AbstractScanAgent {
	private static final Logger log = Logger.getLogger(ZapScanAgent.class);

    private int maxSpiderWaitInSeconds;
    private int maxScanWaitInSeconds;
    private int spiderPollWaitInSeconds;
    private int scanPollWaitInSeconds;
    @NotNull
    private String zapHost;
    private int zapPort;
    @NotNull
    private String zapExecutablePath;
    private long zapStartupWaitTime;
	private Process process;
	
	/**
	 * @param theConfig configuration for the scan. A pre-configured session file can
	 * be passed via the configFile data blob.
	 */
	@Nullable
    private static ZapScanAgent instance = null;
	private ZapScanAgent() {
	}
	@Nullable
    public static ZapScanAgent getInstance(@NotNull Scanner scanner, @NotNull String workDir) {
		if(instance == null) {
			instance = new ZapScanAgent();
		}
		instance.readConfig(ConfigurationUtils.getPropertiesFile());
		instance.setWorkDir(workDir);
		instance.setZapExecutablePath(scanner.getHomeDir());
		instance.setZapHost(scanner.getHost());
		instance.setZapPort(scanner.getPort());
		return instance;
	}
	
    @Nullable
    @Override
	public File doTask(@NotNull TaskConfig theConfig) {

		File retVal = null;

		log.info("Attempting to do ZAP task with config: " + theConfig);
		log.info("Target URL is " + theConfig.getTargetUrlString());
		ClientApi zap = new ClientApi(zapHost, zapPort);
		boolean status;
		try {
			status = startZap();
			if(status) {
				String message = "ZAP should be started";
				log.info(message);
				sendStatusUpdate(message);
				
				log.info("Creating ZAP ClientApi");

				log.info("ZAP ClientApi created");

				//	Determine if we need to set up a session for ZAP or if this is
				//	just an authenticated scan of the URL
				byte[] configFileData = theConfig.getDataBlob("configFile");
				if(configFileData != null) {
					log.debug("Task configuration has configuration file data. Attempting to set session");
					//	Set up the session for ZAP to use
					try {
						FileUtils.deleteDirectory(new File(this.getWorkDir()));
						log.debug("Deleted old working directory. Going to attempt to re-create");
						boolean dirCreate = new File(this.getWorkDir()).mkdirs();
						if(!dirCreate) {
							message = "Unable to re-create working directory. This will end well...";
							log.warn(message);
							sendStatusUpdate(message);
						}

						//	Take the config file ZIP data, save it to the filesystem and extract it
						//	TODO - Look at streaming this from memory. Should be faster than saving/reloading
						String zippedSessionFilename = this.getWorkDir() + File.separator + "ZAPSESSION.zip";
						FileUtils.writeByteArrayToFile(new File(zippedSessionFilename), configFileData);
						ZipFileUtils.unzipFile(zippedSessionFilename, this.getWorkDir());

						//	Now point ZAP toward the unpacked session file
						ApiResponse response;
						log.debug("Setting ZAP home directory to: " + this.getWorkDir());
						response = zap.core.setHomeDirectory(this.getWorkDir());
						log.debug("Loading session");
						response = zap.core.loadSession("ZAPTEST");
						log.debug("Response after attempting set session: " + response.toString(0));
					} catch (ClientApiException e) {
						message = "Problems setting session: " + e.getMessage();
						log.error(message, e);
						sendStatusUpdate(message);
					} catch (IOException e) {
						message = "Problems unpacking the ZAP session data into the working directory: " + e.getMessage();
						log.error(message, e);
						sendStatusUpdate(message);
					}
				} else {
					log.debug("Task configuration had no configuration file data. Will run a default unauthenticated scan.");
				}

				status = attemptRunSpider(theConfig, zap);
				if(status) {
					message = "Appears that spider run was successful. Going to attempt a scan.";
					log.info(message);
					sendStatusUpdate(message);

					status = attemptRunScan(theConfig, zap);

					if(status) {
						message = "Appears that scan run was successful. Going to attempt to pull results";
						log.info(message);
						sendStatusUpdate(message);

						String resultsXml = attemptRetrieveResults();
						if (resultsXml == null || resultsXml.isEmpty())
							return null;
						try {
							String resultsFilename = this.getWorkDir() + File.separator + "ZAPRESULTS.xml";
							log.debug("Writing results to file: " + resultsFilename);
							retVal = new File(resultsFilename);
							FileUtils.writeStringToFile(retVal, resultsXml);
						} catch (IOException ioe) {
							message = "Unable to write results file: " + ioe.getMessage();
							log.error(message, ioe);
							sendStatusUpdate(message);
							retVal = null;
						}

					} else {
						message = "Appears that scan run was unsuccessful. Not going to pull results";
						log.warn(message);
						sendStatusUpdate(message);
					}
				} else {
					message = "Appears that spider run was unsuccessful. Not going to attempt a scan.";
					log.warn(message);
					sendStatusUpdate(message);
				}				
			} else {
				String message = "ZAP does not appear to have started. This will end well...";
				log.warn(message);
				sendStatusUpdate(message);
			}			
		}
		finally {
			stopZap(zap);
		}
		log.info("Finished attempting to do ZAP task with config: " + theConfig);
		return(retVal);
	}

	@Override
	public boolean readConfig(@NotNull Configuration config) {
		boolean retVal = false;
		
		this.maxSpiderWaitInSeconds = config.getInt("zap.maxSpiderWaitInSeconds");
		this.maxScanWaitInSeconds = config.getInt("zap.maxScanWaitInSeconds");
		this.spiderPollWaitInSeconds = config.getInt("zap.spiderPollWaitInSeconds");
		this.scanPollWaitInSeconds = config.getInt("zap.scanPollWaitInSeconds");
		//	TODO rename this to reflect that it is in seconds (also requires change to .properties file)
		this.zapStartupWaitTime = config.getInt("zap.zapStartupWaitTime");
		
		//	TODO - Perform some input validation on the supplied properties so this retVal means something
		retVal = true;
		
		return(retVal);
	}
	
	private boolean startZap() {
		boolean retVal = false;
		log.info("Attempting to start ZAP instance");
		
	    String separator = System.getProperty("file.separator");
	    String path = System.getProperty("java.home")
	            + separator + "bin" + separator + "java";
	    
//	    String starter;
//	    System.out.println("starter init: ");
//		try {
//			System.out.println("scanagent.properties: " + ZapScanAgent.class.getClassLoader().getResource("scanagent.properties").toURI());
//			System.out.println("zapStarter.jar: " + ZapScanAgent.class.getClassLoader().getResource("zapStarter.jar"));
//			File file = new File(ZapScanAgent.class.getClassLoader().getResource("zapStarter.jar").toString());
//			starter = file.getAbsolutePath();
//		} catch (URISyntaxException e1) {
//			log.error("Problems reading jar file: " + e1.getMessage(), e1);
//			return false;
//		}
//		System.out.println("starter: " + starter);
	    ProcessBuilder processBuilder = 
	            new ProcessBuilder(path, "-jar", 
	            		"zapStarter.jar",
	            zapExecutablePath,
	            String.valueOf(zapStartupWaitTime/2));	    

	    log.info("Going to attempt creating new JVM to start ZAP.");
		
		try {
			setProcess(processBuilder.start());
			
			log.info("Creating new JVM to start ZAP. Waiting " + (zapStartupWaitTime) + "s for ZAP to come online");
			Thread.sleep(zapStartupWaitTime * 1000);
			retVal = true;
		} catch (IOException e) {
			log.error("Problems starting new JVM instance. Please check java environment variables.");
			
		} catch (InterruptedException ie) {
			log.error("Problems waiting for JVM instance to start up: " + ie.getMessage(), ie);
		} catch (Exception e) {
			log.error("Cannot start JVM: " + e.getMessage(), e);
		}
		return retVal;
	}
	
	private void stopZap(@NotNull ClientApi zap) {
		log.info("Attempting to shut down ZAP instance");
		ApiResponse result;
		
		try {
			result = zap.core.shutdown();
			if(didCallSucceed(result)) {
				log.info("ZAP shutdown appears to have been successful");
			} else if(didCallFail(result)) {
				log.info("ZAP shutdown request appears to have failed");
			} else {
				log.warn("Got unexpected result from ZAP shutdown request");
			}
		} catch (ClientApiException e) {
			log.error("Problems telling ZAP to shut down: " + e.getMessage(), e);
		} 
		log.info("Finished shutting down ZAP instance");
	}

	
	/**
	 * @return
	 */
	@Nullable
    private String attemptRetrieveResults() {
		String retVal = null;
		
		try {
			Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(this.zapHost, this.zapPort));
			retVal = openUrlViaProxy(proxy);
			if(retVal != null) {
				log.debug("Length of response file from ZAP is: " + retVal.length());
			} else {
				log.warn("Got a null response file from ZAP");
			}
		} catch (Exception e) {
			log.error("Problems retrieving ZAP result. There's might something wrong with zap host/port, " +
					"please check them again and use '-cs zap' to config zap information");
		}
		
		return(retVal);
	}
	
	/**
	 * This code taken from:
	 * https://code.google.com/p/zaproxy-test/source/browse/branches/beta/src/org/zaproxy/zap/DaemonWaveIntegrationTest.java
	 * It has been updated to return a full String with the response rather than a 
	 * List of Strings containing the individual chunks of the response.
	 * 
	 * TODO - Look through and clean up if necessary
	 * TODO - Clean up the massive Exception being thrown
	 * 
	 * @param proxy
	 * @return
	 * @throws Exception
	 */
    @NotNull
    private static String openUrlViaProxy (@NotNull Proxy proxy) throws Exception {
    	StringBuilder response = new StringBuilder();
        URL url = new URL("http://zap/OTHER/core/other/xmlreport/");
        HttpURLConnection uc = (HttpURLConnection)url.openConnection(proxy);
        uc.connect();
        
        BufferedReader in = new BufferedReader(new InputStreamReader(uc.getInputStream()));

        String inputLine;

        while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
        }

        in.close();
        return response.toString();
}
	
	private boolean attemptRunScan(@NotNull TaskConfig theConfig, @NotNull ClientApi zap) {
		boolean retVal = false;
		ApiResponse response;
		
		try {
			log.info("Attempting to start scan");
			
			response = zap.ascan.scan(theConfig.getTargetUrlString(), "true", "false");
			log.info("Call to start scan returned successfull. Checking to see if scan actually started");
			
			if(didCallSucceed(response)) {
				log.info("Attempt to start scan was successful");
				
				// Now wait for the spider to finish
				boolean keepScanning = true;
				
				long startTime = System.currentTimeMillis();
				long endTime = startTime + (maxScanWaitInSeconds * 1000);
				
				log.info("Scan started around " + startTime + ", will wait until " + endTime);
				
				while(keepScanning) {
					response = zap.ascan.status();
					log.debug("Current scan status: " + extractResponseString(response) + "%");
					try {
						Thread.sleep(scanPollWaitInSeconds * 1000);
					} catch (InterruptedException e) {
						log.error("Thread interruption problem: " + e.getMessage(), e);
					}
				
					if("100".equals(extractResponseString(response))) {
						log.info("Scanning completed at 100%");
						
						//	Check to see if we had any results
						//	TOFIX - Check into these arguments to see what we should really be passing
						response = zap.core.alerts("", "", "");
						// log.debug("Results of scan: " + response.toString(0));
						int numAlerts = extractResponseCount(response);
						log.debug("Got " + numAlerts + " alerts");
						if(numAlerts <= 0) {
							//	TODO - Need to look at how we evaluate success and failure here.
							log.warn("Scan returned no alerts. That is kind of strange");
						} else {
							log.info("Scanning found " + numAlerts + " alerts and appears to have been successful");
							retVal = true;
						}
						
						keepScanning = false;
					} else if(System.currentTimeMillis() > endTime ) {
						log.debug("Scanning timed out");
						keepScanning = false;
					}
				}
				
			} else if(didCallFail(response)) {
				log.warn("Attempt to start scan was NOT succcessful");
			} else {
				log.warn("Got an ApiResponse we didn't expect: " + response.toString(0));
			}
			
			
		} catch (ClientApiException e) {
			log.error("Problems communicating with ZAP:" + e.getMessage(), e);
		}
		
		return(retVal);
	}

	private boolean attemptRunSpider(@NotNull TaskConfig theConfig, @NotNull ClientApi zap) {
		
		boolean retVal = false;
		ApiResponse response;
		
		try {
			log.info("Attempting to start spider");
			
			response = zap.spider.scan(theConfig.getTargetUrlString());
			log.info("Call to start spider returned successfully. Checking to see if spider actually started.");
			
			if(didCallSucceed(response)) {
				log.info("Attempt to start spider was succcessful");
				
				//	Now wait for the spider to finish
				boolean keepSpidering = true;
				
				long startTime = System.currentTimeMillis();
				long endTime = startTime + (maxSpiderWaitInSeconds * 1000);
				
				log.info("Spider started around " + startTime + ", will wait until " + endTime);
				
				while(keepSpidering) {
					response = zap.spider.status();
					log.debug("Current spider status: " + extractResponseString(response) + "%");
					try {
						Thread.sleep(spiderPollWaitInSeconds * 1000);
					} catch (InterruptedException e) {
						log.error("Thread interruption problem: " + e.getMessage(), e);
					}
				
					if("100".equals(extractResponseString(response))) {
						log.info("Spidering completed at 100%");
						
						//	Check to see if we had any results
						response = zap.spider.results();
						// log.debug("Results of spider: " + response.toString(0));
						int numUrls = extractResponseCount(response);
						log.debug("Got " + numUrls + " URLs");
						if(numUrls <= 1) {
							//	TODO - Need to look at how we evaluate success and failure here. I could see
							//	a scenario where an app with a single page would come back with unsuccessful
							//	spiders and never get cleared from the queue.
							log.error("Spidering process only returned a single URL and we started with that one. "
										+ "Spidering probably not successful. Did you start the application?");
						} else {
							log.info("Spidering found " + numUrls + " URLs and appears to have been successful");
							retVal = true;
						}
						
						keepSpidering = false;
					} else if(System.currentTimeMillis() > endTime ) {
						log.debug("Spidering timed out");
						keepSpidering = false;
					}
					
				}
				
			} else if(didCallFail(response)) {
				log.warn("Attempt to start spider was NOT succcessful");
			} else {
				log.warn("Got an ApiResponse we didn't expect: " + response.toString(0));
			}
			
		} catch (ClientApiException e) {
			log.error("Problems communicating with ZAP. Zap might wasn't started correctly, " +
					"please check zap home/host/port again and use '-cs zap' to config zap information");
		}
		
		return(retVal);
	}
	
	/**
	 * 	TOFIX - This is kind of gross, but the ZAP Java API is a little goofy here so we have to compensate a bit.
	 * @param response
	 * @return
	 */
	private static boolean didCallSucceed(@Nullable ApiResponse response) {
		boolean retVal = false;
		if(response != null && "OK".equals(extractResponseString(response))) {
			retVal = true;
		}
		return(retVal);
	}
	
	/**
	 * 	TOFIX - This is kind of gross, but the ZAP Java API is a little goofy here so we have to compensate a bit.
	 * @param response
	 * @return
	 */
	private static boolean didCallFail(@Nullable ApiResponse response) {
		boolean retVal = false;
		if(response != null && "FAIL".equals(extractResponseString(response))) {
			retVal = true;
		}
		return(retVal);
	}
	
	/**
	 * 	TOFIX - This is kind of gross, but the ZAP Java API is a little goofy here so we have to compensate a bit.
	 * @param response
	 * @return
	 */
	@Nullable
    private static String extractResponseString(@Nullable ApiResponse response) {
		String retVal = null;
		if(response != null && response instanceof ApiResponseElement) {
			retVal = ((ApiResponseElement)response).getValue();
		}
		return(retVal);
	}
	
	/**
	 * 	TOFIX - This is kind of gross, but the ZAP Java API is a little goofy here so we have to compensate a bit.
	 * @param response
	 * @return
	 */
	private static int extractResponseCount(@Nullable ApiResponse response) {
		int retVal = -1;
		if(response != null && response instanceof ApiResponseList) {
			retVal = ((ApiResponseList)response).getItems().size();
		}
		return(retVal);
	}
	public void setZapHost(@NotNull String zapHost) {
		this.zapHost = zapHost;
	}
	public void setZapPort(int zapPort) {
		this.zapPort = zapPort;
	}
	public void setZapExecutablePath(@NotNull String zapExecutablePath) {
		this.zapExecutablePath = zapExecutablePath;
	}
	public void setProcess(Process process) {
		this.process = process;
	}
	
}
