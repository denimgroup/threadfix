package com.denimgroup.threadfix.scanagent;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;

public class AcunetixScanAgent extends AbstractScanAgent {
	
	static final Logger log = Logger.getLogger(AcunetixScanAgent.class);
	private String acunetixExecutablePath;

	private static AcunetixScanAgent instance = null;
	private AcunetixScanAgent() {
	}
	public static AcunetixScanAgent getInstance(Scanner scanner, String workDir, ServerConduit serverConduit) {
		if(instance == null) {
			instance = new AcunetixScanAgent();
		}
		instance.setWorkDir(workDir);
		instance.setServerConduit(serverConduit);
		instance.setAcunetixExecutablePath(scanner.getHomeDir());
		return instance;
	}
	
	@Override
	public boolean readConfig(Configuration config) {
		boolean retVal = false;
		
//		this.acunetixExecutablePath = config.getString("acunetix.executablePath");
//		log.debug("Acunetix executable located at path: " + this.acunetixExecutablePath);
//		
//		//	TODO - Perform some input validation on the supplied properties so this retVal means something
//		retVal = true;
		
		return(retVal);
	}

	@Override
	public File doTask(TaskConfig config) {
		
		File retVal = null;
		
		log.info("Setting up command-line arguments for Acunetix scan");
		
		String acunetixExecutable = this.acunetixExecutablePath + File.separator + ConfigurationUtils.ACUNETIX_FILES[0];
		log.debug("Acunetix executable should be located at: " + acunetixExecutable);
		String targetSite = config.getTargetUrlString();
		log.debug("Site to scan: " + targetSite);
		
		String[] args = { acunetixExecutable, "/Scan", targetSite, "/SaveFolder", this.getWorkDir(), "/Save", "/ExportXML" };
		
		log.debug("Going to attempt to run Acunetix with exe/args: " + args);
		
		ProcessBuilder pb = new ProcessBuilder(args);
		pb.directory(new File(this.getWorkDir()));
		pb.redirectErrorStream(true);
		
		try {
			Process p = pb.start();
			log.info("Acunetix started successfully. Begin scanning, this will take sometimes...");
			
			InputStreamReader isr = new InputStreamReader(p.getInputStream());
			BufferedReader br = new BufferedReader(isr);
			
			String lineRead;
			while((lineRead = br.readLine()) != null) {
				String logMessage = "Acunetix out >>> " + lineRead;
				log.debug(logMessage);
				this.sendStatusUpdate(logMessage);
			}
			
			int returnCode = p.waitFor();
			log.info("Acunetix process finished with exit code: " + returnCode);
			
			String resultsFilename = this.getWorkDir() + File.separator + "export.xml";
			retVal = new File(resultsFilename);
			log.info("Returning results via file: " + retVal.getAbsolutePath());
			
		} catch (IOException e) {
			log.error("Problems starting Acunetix instance: " + e.getMessage(), e);
		} catch (InterruptedException e) {
			log.error("Problems waiting for Acunetix to finish: " + e.getMessage(), e);
		}
		
		return(retVal);
	}
	public String getAcunetixExecutablePath() {
		return acunetixExecutablePath;
	}
	public void setAcunetixExecutablePath(String acunetixExecutablePath) {
		this.acunetixExecutablePath = acunetixExecutablePath;
	}

}
