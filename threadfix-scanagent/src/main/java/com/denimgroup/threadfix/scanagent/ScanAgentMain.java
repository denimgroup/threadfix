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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.cli.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.util.ConfigurationUtils;
import org.jetbrains.annotations.NotNull;

public final class ScanAgentMain {

	private static final String SCAN_AGENT_VERSION = "2.0.0-DEVELOPMENT-1";
	
	private static Logger log = Logger.getLogger(ScanAgentMain.class);

	@NotNull
    @SuppressWarnings("static-access")
	private static final Options getOptions() {
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
//				config.setAutoSave(true);

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
						runScanQueue();

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
			@NotNull PropertiesConfiguration config) {
		if (config.getString("scanagent.baseWorkDir","").isEmpty() ||
                config.getString("scanagent.threadFixServerUrl","").isEmpty() ||
                config.getString("scanagent.threadFixApiKey","").isEmpty()) {
			System.out.println("Not found enough server configuration (ThreadFix URL, API Key or Working directory). " +
					"Please run '-s' to set up all of these information.");
			return false;
		}
		return true;
	}

	private static ScannerType isValidScannerType(@NotNull String scanner) {
		return ScannerType.getScannerType(scanner);
	}

	private static void println(String string) {
		System.out.println(string);
	}	
	
	private static void runScanQueue() {
		
		log.info("Starting ThreadFix generic scan agent version " + SCAN_AGENT_VERSION);
		BasicConfigurator.configure();
		log.debug("Logging configured and running");
		log.info("Starting ThreadFix generic scan agent version " + SCAN_AGENT_VERSION);
		
		ScanAgentRunner runner = new ScanAgentRunner();
        runner.setTfClient(new ThreadFixRestClientImpl());
        runner.run();
		log.info("ThreadFix generic scan agent version " + SCAN_AGENT_VERSION + " stopping...");
	}
	
}
