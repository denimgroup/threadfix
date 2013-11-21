package com.denimgroup.threadfix.scanagent.scanners;

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
	public static void main(@Nullable String[] args) {
		System.out.println("Start ZAP");
		if (args == null || args.length ==0) {
			return;
		}
		
		String[] arg= { args[0] + getZapRunnerFile(), "-daemon" };
		ProcessBuilder pb = new ProcessBuilder(arg);
		pb.directory(new File(args[0]));

		try {
			pb.start();
			Thread.sleep(Long.valueOf(args[1]) * 1000);

		} catch (IOException e) {
			System.out.println("Problems starting ZAP instance. Please check zap home directory again and use '-cs zap' to config zap information.");

		} catch (InterruptedException ie) {
			System.out.println("Problems waiting for ZAP instance to start up: " + ie.getMessage());
		} catch (Exception e) {
			System.out.println("Cannot start zap: " + e.getMessage());
		}
		System.out.println("Ended starting ZAP");
	}
	
	@NotNull
    private static String getZapRunnerFile() {
		if (System.getProperty("os.name").contains("Windows"))
			return "zap.bat";
		else return "zap.sh";
					
	}
}
