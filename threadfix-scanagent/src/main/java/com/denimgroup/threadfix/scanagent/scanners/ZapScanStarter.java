package com.denimgroup.threadfix.scanagent.scanners;

import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.io.IOException;

/**
 * This class will be running in another JVM to start ZAP 
 * @author stran
 *
 */
public class ZapScanStarter {

    private static Logger LOG = Logger.getLogger(ZapScanStarter.class);

    public static void main(@Nullable String[] args) {
        LOG.info("Start ZAP");
		if (args == null || args.length == 0) {
			return;
		}
		
		String[] processArgs = { args[0] + getZapRunnerFile(), "-daemon" };
		ProcessBuilder pb = new ProcessBuilder(processArgs);
		pb.directory(new File(args[0]));

		try {
			pb.start();
			Thread.sleep(Long.valueOf(args[1]) * 1000);
            LOG.info("Finished waiting for ZAP with no exception.");
		} catch (IOException e) {
			LOG.error("Problems starting ZAP instance. Please check zap home directory again and use " +
                    "'-cs zap' to config zap information.", e);
		} catch (InterruptedException ie) {
			LOG.error("Problems waiting for ZAP instance to start up: " + ie.getMessage(), ie);
		} catch (Exception e) {
			LOG.error("Cannot start zap: " + e.getMessage(), e);
		}

        LOG.info("Exiting ZapScanStarter");
	}
	
	@NotNull
    private static String getZapRunnerFile() {
        return System.getProperty("os.name").contains("Windows") ? "zap.bat" : "zap.sh";
	}
}
