package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.File;

public class ConfigurationChecker {

    private static final Logger LOG = Logger.getLogger(
            ConfigurationChecker.class);

    public static boolean hasInvalidServerConnection() {
        ThreadFixRestClient client = new ThreadFixRestClientImpl(
                new ScanAgentPropertiesManager());

        RestResponse<Organization[]> allTeams = client.getAllTeams();

        if (allTeams.success && allTeams.responseCode == 200) {
            return false;
        } else {
            LOG.error("Unable to connect to ThreadFix server. Message: " + allTeams.message);
            return true;
        }
    }

    public static boolean hasIncompleteProperties() {
        String workingDirectory = ScanAgentPropertiesManager.getWorkingDirectory(),
                url = ScanAgentPropertiesManager.getUrlStatic(),
                key = ScanAgentPropertiesManager.getKeyStatic();

        return workingDirectory == null || workingDirectory.isEmpty() ||
                url == null || url.isEmpty() ||
                key == null || key.isEmpty();
    }

    public static boolean hasInvalidWorkDirectory() {
        return !isDirectory(ScanAgentPropertiesManager.getWorkingDirectory());
    }

    public static boolean isDirectory(String path) {
        File file = new File(path);
        return file.exists() && file.isDirectory();
    }

    public static boolean checkHomeParam(@NotNull ScannerType scannerType, @NotNull String home) {
        String osName = System.getProperty("os.name");

        File resultingFile = null;

        if (scannerType == ScannerType.ZAPROXY) {
            if (osName.contains("Windows")) {
                resultingFile = new File(home +
                        ConfigurationUtils.ZAP_FILES[0]);
            } else {
                resultingFile = new File(home +
                        ConfigurationUtils.ZAP_FILES[1]);
            }
        } else if (scannerType == ScannerType.ACUNETIX_WVS) {
            resultingFile = new File(home +
                    ConfigurationUtils.ACUNETIX_FILES[0]);
        } else if (scannerType == ScannerType.APPSCAN_DYNAMIC) {
            resultingFile = new File(home +
                    ConfigurationUtils.APP_SCAN_FILES[0]);
        }

        return resultingFile != null &&
                resultingFile.isFile() && resultingFile.exists();
    }
}
