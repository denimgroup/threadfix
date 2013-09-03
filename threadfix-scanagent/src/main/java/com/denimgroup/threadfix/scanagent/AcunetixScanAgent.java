package com.denimgroup.threadfix.scanagent;

import java.io.File;
import java.io.IOException;

import org.apache.commons.configuration.Configuration;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.data.entities.TaskConfig;

public class AcunetixScanAgent extends AbstractScanAgent {
	
	static final Logger log = Logger.getLogger(AcunetixScanAgent.class);
	private String acunetixExecutablePath;

	@Override
	public boolean readConfig(Configuration config) {
		boolean retVal = false;
		
		this.acunetixExecutablePath = config.getString("acunetix.executablePath");
		
		//	TODO - Perform some input validation on the supplied properties so this retVal means something
		retVal = true;
		
		return(retVal);
	}

	@Override
	public Object doTask(TaskConfig config) {			
		log.info("Attempting to start Acunetix instance");
		
		String acunetixExecutable = this.acunetixExecutablePath + "wvs_console.exe";
		String[] args = { acunetixExecutable,  };
		
		log.debug("Going to attempt to run ZAP executable at: " + args[0]);
		
		ProcessBuilder pb = new ProcessBuilder(args);
		pb.directory(new File(zapExecutablePath));
		
		try {
			pb.start();
			log.info("ZAP started successfully. Waiting " + (this.zapStartupWaitTime) + "s for ZAP to come online");
			Thread.sleep(this.zapStartupWaitTime * 1000);
			retVal = true;
		} catch (IOException e) {
			log.error("Problems starting ZAP instance: " + e.getMessage(), e);
		} catch (InterruptedException ie) {
			log.error("Problems waiting for ZAP instance to start up: " + ie.getMessage(), ie);
		}
			


		
		return null;
	}

}
