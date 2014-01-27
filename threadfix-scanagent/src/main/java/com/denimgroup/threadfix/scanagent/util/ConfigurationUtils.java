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

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.scanagent.ScanAgentConfigurationUnavailableException;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class ConfigurationUtils {
	private static Logger log = Logger.getLogger(ConfigurationUtils.class);
	
	@NotNull
    public static String[] ZAP_FILES = new String[]{"zap.bat", "zap.sh"};
	@NotNull
    public static String[] ACUNETIX_FILES = new String[]{"wvs_console.exe"};
    @NotNull
    public static String[] APP_SCAN_FILES = new String[]{"AppScanCMD.exe"};

	/**
	 * Read all the scanner has been set up in scanagent properties file
	 */
	@NotNull
    public static List<Scanner> readAllScanner() {
		log.info("Start reading all scanner type");
		List<Scanner> scanners = new ArrayList<>();
        Configuration config = getPropertiesFile();
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
	
	private static void writeToFile(@NotNull String[] names, @NotNull String[] values) {
		
		if (names.length != values.length) {
			return;
		}
        Configuration config = getPropertiesFile();
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
        return file.exists() && file.isDirectory();
    }

    public static boolean isFile(String path) {
        File file = new File(path);
        return file.exists() && file.isFile();
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
		} else if (scannerType == ScannerType.APPSCAN_DYNAMIC) {
            File acuExeFile = new File(home + APP_SCAN_FILES[0]);
            if (!acuExeFile.exists() || !acuExeFile.isFile()) {
                return false;
            }
        }
		return true;
	}
	
	/**
	 * This method config the information for Scanner
	 * @param scannerType
	 */
	public static void configScannerType(@NotNull ScannerType scannerType) {

		System.out.println("Start configuration for " + scannerType.getFullName());
		Scanner scanner = new Scanner();
        scanner.setName(scannerType.getFullName());
        java.util.Scanner in = null;
        try {
            in = new java.util.Scanner(System.in);

            if (scannerType == ScannerType.BURPSUITE) {
                inputBurpRunFile(scanner,in);
            } else {
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
                        scanner.setHomeDir(home);
                    } else {
                        System.out.println(scannerType.getFullName() + " home directory is invalid!");
                    }
                }
            }
            // Input scanner version
            System.out.print("Input " + scannerType.getFullName() + " version: ");
            scanner.setVersion(in.nextLine());

            inputMoreScanInfo(scannerType, scanner, in);

            scanner.saveInformation();

        } finally {
			if (in != null) {
				in.close();
			}
		}
		System.out.println("Ended configuration for " + scannerType.getFullName() + ". Congratulations!");
		System.out.println("Run '-r' to execute scan queue task from Threadfix server.");
	}

    private static void inputBurpRunFile( @NotNull Scanner scan, @NotNull java.util.Scanner in) {
        boolean isValidPath = false;
        while (!isValidPath) {
            System.out.print("Input full path for Burp Suite jar file (Ex: C:\\Burp\\burp.jar): ");
            String fileName = in.nextLine();
            if (isFile(fileName)) {
                isValidPath = true;
                scan.setHomeDir(fileName);
            } else {
                System.out.println("Burp Suite jar file is invalid!");
            }
        }
    }

	private static void inputMoreScanInfo(@NotNull ScannerType scannerType,
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
			writeToFile(new String[]{scannerType.getShortName()+".loginSeqDir"}, new String[]{loginSeqDir});
		}

	}

	public static void configSystemInfo() {
		System.out.println("Starting configuration dialog.");
		try (java.util.Scanner in = new java.util.Scanner(System.in)) {

            boolean keepGoing = true;
            while (keepGoing) {
                // Input Threadfix base Url
                System.out.print("Input ThreadFix base URL (should end in /rest): ");
                ScanAgentPropertiesManager.saveUrl(in.nextLine());

                // Input ThreadFix API key
                System.out.print("Input ThreadFix API key: ");
                ScanAgentPropertiesManager.saveKey(in.nextLine());

                keepGoing = ConfigurationUtils.hasInvalidServerConnection();
                if (keepGoing) {
                    System.out.println("The configuration given was invalid. Please try again.");
                }
            }
			
			// Input working directory
			boolean isValidDir = false;
			while (!isValidDir) {
				System.out.print("Input working directory (is where to export scan result files): ");
				String workdir = in.nextLine();
				if (isDirectory(workdir)) {
					ScanAgentPropertiesManager.saveWorkDirectory(workdir);
					isValidDir = true;
				} else {
					System.out.println("Directory is invalid.");
				}
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
		} else if (scanner == ScannerType.APPSCAN_DYNAMIC) {
            exeName = APP_SCAN_FILES[0];
        }
		return exeName;
	}
	
	@NotNull
    public static PropertiesConfiguration getPropertiesFile() {
		try {
            PropertiesConfiguration config = new PropertiesConfiguration("scanagent.properties");
            config.setAutoSave(true);
            return config;
		} catch (ConfigurationException e) {
            String message = "Problems reading configuration: " + e.getMessage();
			log.error(message, e);
            throw new ScanAgentConfigurationUnavailableException(message, e);
		}
	}

    public static boolean hasInvalidServerConnection() {
        ThreadFixRestClient client = new ThreadFixRestClientImpl(new ScanAgentPropertiesManager());

        RestResponse<Organization[]> allTeams = client.getAllTeams();

        if (allTeams.success && allTeams.responseCode == 200) {
            return false;
        } else {
            log.error("Unable to connect to ThreadFix server. Message: " + allTeams.message);
            return true;
        }
    }

    public static boolean hasIncompleteProperties() {
        PropertiesConfiguration configuration = getPropertiesFile();
        return configuration.getString("scanagent.baseWorkDir", "").isEmpty() ||
                configuration.getString("scanagent.threadFixServerUrl","").isEmpty() ||
                configuration.getString("scanagent.threadFixApiKey","").isEmpty();
    }

}
