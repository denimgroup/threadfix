package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.scanagent.configuration.Scanner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;

public class ConfigurationDialogs {

    public static void configSystemInfo() {
        System.out.println("Starting configuration dialog.");
        try (java.util.Scanner in = new java.util.Scanner(System.in)) {

            boolean keepGoing = true;
            while (keepGoing) {
                // Input ThreadFix base Url
                System.out.println("Input ThreadFix base URL (should end in /rest, leave empty to keep " +
                        ScanAgentPropertiesManager.getUrlStatic() + "): ");

                String input = in.nextLine();
                if (!input.trim().isEmpty()) {
                    ScanAgentPropertiesManager.saveUrl(input);
                }

                // Input ThreadFix API key
                System.out.println("\nInput ThreadFix API key (leave empty to keep " +
                        ScanAgentPropertiesManager.getKeyStatic() + "): ");

                input = in.nextLine();
                if (!input.trim().isEmpty()) {
                    ScanAgentPropertiesManager.saveKey(input);
                }

                keepGoing = ConfigurationChecker.hasInvalidServerConnection();
                if (keepGoing) {
                    System.out.println("\nThe configuration given was invalid. Please try again.");
                }
            }

            configWorkDirectory();
        }
        System.out.println("Ended configuration. Congratulations!");
        System.out.println("Run '-cs <ScannerName>' to config Scanner or '-r' to execute scan queue task from Threadfix server" +
                " if you already set up Scanner");
    }

    public static void configWorkDirectory() {

        try (java.util.Scanner in = new java.util.Scanner(System.in)) {
            // Input working directory
            boolean isValidDir = false;
            while (!isValidDir) {
                System.out.println("Input working directory (for file storage, leave empty to keep " +
                        ScanAgentPropertiesManager.getWorkingDirectory() + "): ");
                String workdir = in.nextLine();
                if (ConfigurationChecker.isDirectory(workdir)) {
                    ScanAgentPropertiesManager.saveWorkDirectory(workdir);
                    isValidDir = true;
                } else {
                    System.out.println("Directory is invalid.");
                }
            }
        }
    }

    /**
     * This method config the information for Scanner
     */
    public static void configScannerType(@NotNull ScannerType scannerType) {

        System.out.println("Start configuration for " + scannerType.getFullName());
        Scanner scanner = new Scanner();
        scanner.setName(scannerType.getFullName());
        try (java.util.Scanner in = new java.util.Scanner(System.in)) {
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
                    if (ConfigurationChecker.checkHomeParam(scannerType, home)) {
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
        }

        System.out.println("Ended configuration for " + scannerType.getFullName() + ". Congratulations!");
        System.out.println("Run '-r' to execute scan queue task from Threadfix server.");
    }

    public static boolean isFile(String path) {
        File file = new File(path);
        return file.exists() && file.isFile();
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
                isValidDir = ConfigurationChecker.isDirectory(loginSeqDir);
                if (!isValidDir)
                    System.out.println("Unable to find this directory.");
            }
            ScanAgentPropertiesManager.writeProperty(
                    scannerType.getShortName()+".loginSeqDir", loginSeqDir);
        }

    }

    @Nullable
    private static String getExeFile(@NotNull ScannerType scanner) {
        String exeName = null;
        if (scanner == ScannerType.ZAPROXY) {
            exeName = ConfigurationUtils.ZAP_FILES[0] + "/" +
                    ConfigurationUtils.ZAP_FILES[1];
        } else if (scanner == ScannerType.ACUNETIX_WVS) {
            exeName = ConfigurationUtils.ACUNETIX_FILES[0];
        } else if (scanner == ScannerType.APPSCAN_DYNAMIC) {
            exeName = ConfigurationUtils.APP_SCAN_FILES[0];
        }
        return exeName;
    }
}
