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

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

public class AppScanScanAgent extends AbstractScanAgent {

	private static final Logger log = Logger.getLogger(AppScanScanAgent.class);
	@NotNull
    private String appScanExecutablePath;
    @Nullable
	private static AppScanScanAgent instance = null;
	private AppScanScanAgent() {
	}
	@Nullable
    public static AppScanScanAgent getInstance(@NotNull Scanner scanner, @NotNull String workDir) {
		if(instance == null) {
			instance = new AppScanScanAgent();
		}
		instance.readConfig(ConfigurationUtils.getPropertiesFile());
		instance.setWorkDir(workDir);
		instance.setAppScanExecutablePath(scanner.getHomeDir());
		return instance;
	}
	
	@Override
	public boolean readConfig(@NotNull Configuration config) {
		boolean retVal = false;
		return retVal;
	}

    @Nullable
    @Override
	public File doTask(@NotNull TaskConfig config) {
		
		File retVal = null;
        String resultsFilename = this.getWorkDir() + File.separator + "AppScan_export.xml";
		String[] args = setupArgs(config, resultsFilename);

        if (args == null) {
            log.error("Scanning wasn't executed.");
            return retVal;
        }

		log.debug("Going to attempt to run AppScan Standard with exe/args: " + Arrays.toString(args));

		ProcessBuilder pb = new ProcessBuilder(args);
		pb.directory(new File(this.getWorkDir()));
		pb.redirectErrorStream(true);
		
		try {
			Process p = pb.start();
			log.info("AppScan Standard started successfully. Begin scanning, this will take sometimes...");
			
			InputStreamReader isr = new InputStreamReader(p.getInputStream());
			BufferedReader br = new BufferedReader(isr);
			
			String lineRead;
			while((lineRead = br.readLine()) != null) {
				String logMessage = "AppScan Standard out >>> " + lineRead;
				log.debug(logMessage);
				this.sendStatusUpdate(logMessage);
			}
			
			int returnCode = p.waitFor();
			log.info("AppScan Standard process finished with exit code: " + returnCode);
            if (returnCode != 0) {
                log.warn("Scanning was not successful.");
            }
			
			retVal = new File(resultsFilename);
			log.info("Returning results via file: " + retVal.getAbsolutePath());
			
		} catch (IOException e) {
			log.error("Problems starting AppScan Standard instance: " + e.getMessage(), e);
		} catch (InterruptedException e) {
			log.error("Problems waiting for AppScan Standard to finish: " + e.getMessage(), e);
		}
		
		return retVal;
	}
	
	@Nullable
    private String[] setupArgs(@NotNull TaskConfig config, @NotNull String resultsFilename) {
		log.info("Setting up command-line arguments for AppScan Standard scan");
		
		String appScanExecutable = this.appScanExecutablePath + ConfigurationUtils.APP_SCAN_FILES[0];
		log.debug("AppScan Standard executable should be located at: " + appScanExecutable);
		String targetSite = config.getTargetUrlString();
		log.debug("Site to scan: " + targetSite);
		
		byte[] configFileBytes = config.getDataBlob("configFile");
		
		String[] args = null; 
		
		if (configFileBytes != null) {
			String baseScan = this.getWorkDir() + File.separator + "baseScan.scan";
            String destScan = this.getWorkDir() + File.separator + "destScan.scan";

			try {
				FileUtils.writeByteArrayToFile(new File(baseScan), configFileBytes);
				args = new String[] { appScanExecutable, "exec", "/b", baseScan, "/d", destScan,
                        "/rf", resultsFilename, "/rt", "xml" };
			} catch (IOException e1) {
				log.warn("Unable to save appscan config file to working dir");
				e1.printStackTrace();
			}
		} else {
			log.error("AppScan needs base scan file in order to do scanning, please attach base scan file to ThreadFix application!!!");
        }
		return args;
	}

	public void setAppScanExecutablePath(@NotNull String appScanExecutablePath) {
		this.appScanExecutablePath = appScanExecutablePath;
	}

}
