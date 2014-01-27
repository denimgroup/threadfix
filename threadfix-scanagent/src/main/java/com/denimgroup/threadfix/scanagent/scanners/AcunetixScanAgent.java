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

public class AcunetixScanAgent extends AbstractScanAgent {
	
	private static final Logger LOG = Logger.getLogger(AcunetixScanAgent.class);
	@NotNull
    private String acunetixExecutablePath;
	private String loginSeqDir;
    @Nullable
	private static AcunetixScanAgent instance = null;

	private AcunetixScanAgent() {}

	@Nullable
    public static AcunetixScanAgent getInstance(@NotNull Scanner scanner, @NotNull String workDir) {
		if(instance == null) {
			instance = new AcunetixScanAgent();
		}
		instance.readConfig(ConfigurationUtils.getPropertiesFile());
		instance.setWorkDir(workDir);
		instance.setAcunetixExecutablePath(scanner.getHomeDir());
		return instance;
	}
	
	@Override
	public boolean readConfig(@NotNull Configuration config) {
		this.loginSeqDir = config.getString(ScannerType.ACUNETIX_WVS.getShortName() + ".loginSeqDir");
        return loginSeqDir != null;
	}

    @Nullable
    @Override
	public File doTask(@NotNull TaskConfig config) {
		
		File retVal = null;
		
		String[] args = setupArgs(config);
		
		LOG.debug("Going to attempt to run Acunetix with exe/args: " + Arrays.toString(args));

		ProcessBuilder pb = new ProcessBuilder(args);
		pb.directory(new File(this.getWorkDir()));
		pb.redirectErrorStream(true);
		
		try {
			Process p = pb.start();
			LOG.info("Acunetix started successfully. Begin scanning, this will take sometimes...");
			
			InputStreamReader isr = new InputStreamReader(p.getInputStream());
			BufferedReader br = new BufferedReader(isr);
			
			String lineRead;
			while((lineRead = br.readLine()) != null) {
				String logMessage = "Acunetix out >>> " + lineRead;
				LOG.debug(logMessage);
				this.sendStatusUpdate(logMessage);
			}
			
			int returnCode = p.waitFor();
			LOG.info("Acunetix process finished with exit code: " + returnCode);
			
			String resultsFilename = this.getWorkDir() + File.separator + "export.xml";
			retVal = new File(resultsFilename);
			LOG.info("Returning results via file: " + retVal.getAbsolutePath());
			
		} catch (IOException e) {
			LOG.error("Problems starting Acunetix instance: " + e.getMessage(), e);
		} catch (InterruptedException e) {
			LOG.error("Problems waiting for Acunetix to finish: " + e.getMessage(), e);
		}
		
		return retVal;
	}
	
	@Nullable
    private String[] setupArgs(@NotNull TaskConfig config) {
		LOG.info("Setting up command-line arguments for Acunetix scan");
		
		String acunetixExecutable = this.acunetixExecutablePath + ConfigurationUtils.ACUNETIX_FILES[0];
		LOG.debug("Acunetix executable should be located at: " + acunetixExecutable);
		String targetSite = config.getTargetUrlString();
		LOG.debug("Site to scan: " + targetSite);
		
		byte[] configFileBytes = config.getDataBlob("configFile");
		
		String[] args = null; 
		
		if (configFileBytes != null) {
			String configFileName = this.getLoginSeqDir() + File.separator + "acunetixConfig.loginseq";

			try {
				FileUtils.writeByteArrayToFile(new File(configFileName), configFileBytes);
				args = new String[] { acunetixExecutable, "/Scan", targetSite, "/SaveFolder", 
						this.getWorkDir(), "/Save", "/ExportXML", "/LoginSeq", "acunetixConfig" };
			} catch (IOException e1) {
				LOG.warn("Unable to save acunetix config file to working dir");
				e1.printStackTrace();
			}
		}

		if (args == null)	
			args = new String[] { acunetixExecutable, "/Scan", targetSite, "/SaveFolder", this.getWorkDir(), "/Save", "/ExportXML" };
		
		return args;
	}

	public void setAcunetixExecutablePath(@NotNull String acunetixExecutablePath) {
		this.acunetixExecutablePath = acunetixExecutablePath;
	}
	public String getLoginSeqDir() {
		return loginSeqDir;
	}

}
