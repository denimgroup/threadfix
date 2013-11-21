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
package com.denimgroup.threadfix.scanagent.util;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class ConfigurationUtils {
	private static Logger log = Logger.getLogger(ConfigurationUtils.class);
	
	@NotNull
    public static String[] ZAP_FILES = new String[]{"zap.bat", "zap.sh"};
	@NotNull
    public static String[] ACUNETIX_FILES = new String[]{"wvs_console.exe"};
	
	public static void saveUrlConfig(@NotNull String url, @NotNull Configuration config) {
//		log.info("Start saving url");
		writeToFile(new String[]{"scanagent.threadFixServerUrl"}, new String[]{url}, config);
//		log.info("Ended saving url");
	}
	
	public static void saveKeyConfig(@NotNull String key, @NotNull Configuration config) {
//		log.info("Start saving key");
		writeToFile(new String[]{"scanagent.threadFixApiKey"}, new String[]{key}, config);
//		log.info("Ended saving key");
	}
	
	public static void saveWorkDirectory(@NotNull String workdir, @NotNull Configuration config) {
//		log.info("Start saving working directory");
		writeToFile(new String[]{"scanagent.baseWorkDir"}, new String[]{workdir}, config);
//		log.info("Ended saving working directory");
	}
	
	public static void saveScannerType(@NotNull Scanner scan, @NotNull Configuration config) {
//		log.info("Start saving scanner type");
		String[] names = new String[5];
		String[] values = new String[5];

		ScannerType type = ScannerType.getScannerType(scan.getName());
		String name = type.getShortName();
		names[0] = type.getShortName() + ".scanName";
		values[0] = type.getFullName();
		names[1] = name + ".scanVersion";
		names[2] = name + ".scanExecutablePath";
		names[3] = name + ".scanHost";
		names[4] = name + ".scanPort";
		values[1] = scan.getVersion();
		values[2] = scan.getHomeDir();
		values[3] = scan.getHost();
		values[4] = String.valueOf(scan.getPort());
		writeToFile(names, values, config);
//		log.info("Ended saving scanner type");
	}
	
	/**
	 * Read all the scanner has been set up in scanagent properties file
	 * @param config
	 * @return
	 */
	@NotNull
    public static List<Scanner> readAllScanner(@NotNull Configuration config) {
		log.info("Start reading all scanner type");
		List<Scanner> scanners = new ArrayList<>();
		
		try {
			for (ScannerType type : ScannerType.values()) {
				Scanner scan = new Scanner();
				String scanName = config.getString(type.getShortName() + ".scanName");
				if (scanName != null && !scanName.isEmpty()) {
					scan.setName(scanName);
					scan.setVersion(config.getString(type.getShortName() + ".scanVersion"));
					scan.setHomeDir(config.getString(type.getShortName() + ".scanExecutablePath"));
					scan.setHost(config.getString(type.getShortName() + ".scanHost"));
					scan.setPort(Integer.valueOf(config.getString(type.getShortName() + ".scanPort")));
					scanners.add(scan);
				}
			}
		} catch (Exception e) {
			log.error("Problems reading configuration: " + e.getMessage(), e);
			return scanners;
		}
		
		log.info("Number of scanners available: " + scanners.size());
		return scanners;
	}
	
	private static void writeToFile(@NotNull String[] names, @NotNull String[] values, @NotNull Configuration config) {
		
		if (names.length != values.length) {
			return;
		}
		
		for (int i=0;i<names.length;i++) {
			String name = names[i];
			if (config.getString(name,"").isEmpty()) {
				config.addProperty(name, values[i]);
			} else {
				config.setProperty(name, values[i]);
			}
		}
	}
	
	public static boolean isDirectory(String path) {
		File file = new File(path);
		if (!file.exists() || !file.isDirectory()) {
			return false;
		}
		return true;
	}

	public static boolean checkHomeParam(@NotNull ScannerType scannerType, @NotNull String home) {

		String osName = System.getProperty("os.name");

		if (scannerType == ScannerType.ZAPROXY) {
			if (osName.contains("Windows")) {
				File zapExeFile = new File(home + ZAP_FILES[0]);
				if (!zapExeFile.exists() || !zapExeFile.isFile()) {
					return false;
				}
			} else {
				File zapExeFile = new File(home + ZAP_FILES[1]);
				if (!zapExeFile.exists() || !zapExeFile.isFile()) {
					return false;
				}
			}
		} else if (scannerType == ScannerType.ACUNETIX_WVS) {
			File acuExeFile = new File(home + ACUNETIX_FILES[0]);
			if (!acuExeFile.exists() || !acuExeFile.isFile()) {
				return false;
			}
		}
		return true;
	}
	
	/**
	 * This method config the information for Scanner
	 * @param scannerType
	 * @param config
	 */
	public static void configScannerType(@NotNull ScannerType scannerType,
                                         @NotNull PropertiesConfiguration config) {

		System.out.println("Start configuration for " + scannerType.getFullName());
		Scanner scan = new Scanner();
		scan.setName(scannerType.getFullName());
		java.util.Scanner in = null;
		try {
			in = new java.util.Scanner(System.in);
			// Input scanner home
			boolean isValidHomeDir = false;
			while (!isValidHomeDir) {
				System.out.print("Input " + scannerType.getFullName() + " home directory (is where " + getExeFile(scannerType) +" located): ");
				String home = in.nextLine();
				String separator = System.getProperty("file.separator");
				if (!home.endsWith(separator)) {
					 home = home + separator;
				}
				if (checkHomeParam(scannerType, home)) {
					isValidHomeDir = true;
					scan.setHomeDir(home);
				} else {
					System.out.println(scannerType.getFullName() + " home directory is invalid!");
				}
			}
			
			// Input scanner version
			System.out.print("Input " + scannerType.getFullName() + " version: ");
			scan.setVersion(in.nextLine());
			
			inputMoreScanInfo(config, scannerType, scan, in);
		
			saveScannerType(scan, config);
			
		} finally {
			if (in != null) {
				in.close();
			}
		}
		System.out.println("Ended configuration for " + scannerType.getFullName() + ". Congratulations!");
		System.out.println("Run '-r' to execute scan queue task from Threadfix server.");
	}

	private static void inputMoreScanInfo(@NotNull PropertiesConfiguration config,
                                          @NotNull ScannerType scannerType,
                                          @NotNull Scanner scan,
                                          @NotNull java.util.Scanner in) {

		// Input host and port for ZAP
		if (scannerType == ScannerType.ZAPROXY) {
			System.out.print("Do you want to input host and port for " + scannerType.getFullName() + "(y/n)? ");
			String isContinue = in.nextLine();
			if (isContinue.equalsIgnoreCase("y")) {
				System.out.print("Input " + scannerType.getFullName() + " host: ");
				scan.setHost(in.nextLine());

				boolean isValidPort = false;
				while (!isValidPort) {
					System.out.print("Input " + scannerType.getFullName() + " port: (is port in Option/Local proxy)");
					try {
						int port = Integer.parseInt(in.nextLine());
						scan.setPort(port);
						isValidPort = true;
					}
					catch (NumberFormatException ex) {
						System.out.println("Not a valid port. Please input integer.");
					}
				}
			} else {
				System.out.println("That's fine. System will set the dedault values for them (localhost and 8008).");
				scan.setHost("localhost");
				scan.setPort(8008);
			}
		}
		
		// Input login sequence directory for ACUNETIX
		if (scannerType == ScannerType.ACUNETIX_WVS) {
			String loginSeqDir = null;
			boolean isValidDir = false;
			while (!isValidDir) {
				System.out.println("Input directory where " + scannerType.getFullName() + " " + scan.getVersion() + " " +
						"saves login sequence files: (Suggestion: C:/Users/Public/Documents/Acunetix WVS " + scan.getVersion() + "/LoginSequences)");
				loginSeqDir = in.nextLine();
				isValidDir = isDirectory(loginSeqDir);
				if (!isValidDir) 
					System.out.println("Unable to find this directory.");
			}
			writeToFile(new String[]{scannerType.getShortName()+".loginSeqDir"}, new String[]{loginSeqDir}, config);
		}

	}

	public static void configSystemInfo(@NotNull PropertiesConfiguration config) {
		System.out.println("Start configuration for server information.");
		java.util.Scanner in = null;
		try {
			in = new java.util.Scanner(System.in);
			// Input Threadfix base Url
			System.out.print("Input ThreadFix base Url: ");
			saveUrlConfig(in.nextLine(), config);
			
			// Input ThreadFix API key
			System.out.print("Input ThreadFix API key: ");
			saveKeyConfig(in.nextLine(), config);
			
			// Input working directory
			boolean isValidDir = false;
			while (!isValidDir) {
				System.out.print("Input working directory (is where to export scan result files): ");
				String workdir = in.nextLine();
				if (isDirectory(workdir)) {
					saveWorkDirectory(workdir, config);
					isValidDir = true;
				} else {
					System.out.println("Directory is invalid.");
				}
			}
		} finally {
			if (in != null) {
				in.close();
			}
		}
		System.out.println("Ended configuration. Congratulations!");
		System.out.println("Run '-cs <ScannerName>' to config Scanner or '-r' to execute scan queue task from Threadfix server" +
				" if you already set up Scanner");
	}
	
	@Nullable
    private static String getExeFile(@NotNull ScannerType scanner) {
		String exeName = null;
		if (scanner == ScannerType.ZAPROXY) {
			exeName = ZAP_FILES[0] + "/" + ZAP_FILES[1];
		} else if (scanner == ScannerType.ACUNETIX_WVS) {
			exeName = ACUNETIX_FILES[0];
		}
		return exeName;
	}
	
	@Nullable
    public static PropertiesConfiguration getPropertiesFile() {
		try {
            PropertiesConfiguration config =  new PropertiesConfiguration("scanagent.properties");
            config.setAutoSave(true);
            return config;
		} catch (ConfigurationException e) {
			log.error("Problems reading configuration: " + e.getMessage(), e);
		}
		return null;
	}

}
