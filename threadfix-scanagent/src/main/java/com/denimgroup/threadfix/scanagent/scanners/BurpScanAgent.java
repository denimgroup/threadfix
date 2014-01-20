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

import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
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

public class BurpScanAgent extends AbstractScanAgent {

    private static final String TARGET_URL = "target_url";
    private static final String WORKING_DIRECTORY = "working_directory";
    private static final String STATE_FILE = "state_file";
    private static final String EXPORT_RESULT_FILE_NAME = "burp_scan_result.xml";
    private static final String STATE_FILE_NAME = "application.state";

    private static final Logger log = Logger.getLogger(BurpScanAgent.class);
	@NotNull
    private String burpExecutableFile;
    @Nullable
	private static BurpScanAgent instance = null;
	private BurpScanAgent() {
	}
	@Nullable
    public static BurpScanAgent getInstance(@NotNull Scanner scanner, @NotNull String workDir) {
		if(instance == null) {
			instance = new BurpScanAgent();
		}
		instance.setWorkDir(workDir);
		instance.setBurpExecutableFile(scanner.getHomeDir());
		return instance;
	}
	
	@Override
	public boolean readConfig(@NotNull Configuration config) {
		return true;
	}

    @Nullable
    @Override
	public File doTask(@NotNull TaskConfig config) {
		
		File retVal = null;
		
		String[] args = setupArgs(config);
		
		log.debug("Going to attempt to run Burp Suite with exe/args: " + Arrays.toString(args));

		ProcessBuilder pb = new ProcessBuilder(args);
		pb.directory(new File(this.getWorkDir()));
		pb.redirectErrorStream(true);
		
		try {
			Process p = pb.start();
			log.info("Burp Suite started successfully. Begin scanning, this will take sometimes...");
			
			InputStreamReader isr = new InputStreamReader(p.getInputStream());
			BufferedReader br = new BufferedReader(isr);
			
			String lineRead;
			while((lineRead = br.readLine()) != null) {
				String logMessage = "Burp Suite out >>> " + lineRead;
				log.debug(logMessage);
				this.sendStatusUpdate(logMessage);
			}
			
			int returnCode = p.waitFor();
			log.info("Burp Suite process finished with exit code: " + returnCode);
			
			String resultsFilename = this.getWorkDir() + File.separator + EXPORT_RESULT_FILE_NAME;
			retVal = new File(resultsFilename);
			log.info("Returning results via file: " + retVal.getAbsolutePath());
			
		} catch (IOException e) {
			log.error("Problems starting Burp Suite instance: " + e.getMessage(), e);
		} catch (InterruptedException e) {
			log.error("Problems waiting for Burp Suite to finish: " + e.getMessage(), e);
		}
		
		return retVal;
	}
	
	@Nullable
    private String[] setupArgs(@NotNull TaskConfig config) {
		log.info("Setting up command-line arguments for Burp Suite scan");

		log.debug("Burp Suite executable should be located at: " + this.burpExecutableFile);
		String targetSite = config.getTargetUrlString();
		log.debug("Site to scan: " + targetSite);
		
		byte[] configFileBytes = config.getDataBlob("configFile");
		
		String[] args = null;

        String javaHome = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";
        String burpFile = System.getProperty("user.dir")+ File.separator + "burp-agent.jar;" + this.burpExecutableFile;

        if (configFileBytes != null) {
			String configFileName = this.getWorkDir() + File.separator + STATE_FILE_NAME;

			try {
				FileUtils.writeByteArrayToFile(new File(configFileName), configFileBytes);
                args = new String[]{javaHome, "-Djava.awt.headless=true", "-Xmx1024m", "-classpath", burpFile,
                        "burp.StartBurp", TARGET_URL, targetSite, WORKING_DIRECTORY, this.getWorkDir(),
                        STATE_FILE, STATE_FILE_NAME};
			} catch (IOException e1) {
				log.warn("Unable to save Burp Suite state file to working dir" + e1.getMessage(), e1);
			}
		}

		if (args == null)
            args = new String[]{javaHome, "-Djava.awt.headless=true", "-Xmx1024m", "-classpath", burpFile,
                    "burp.StartBurp", TARGET_URL, targetSite, WORKING_DIRECTORY, this.getWorkDir()};
		
		return args;
	}

	public void setBurpExecutableFile(@NotNull String burpExecutableFile) {
		this.burpExecutableFile = burpExecutableFile;
	}

}
