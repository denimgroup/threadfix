package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.scanagent.ScanAgentConfigurationUnavailableException;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.*;

public class ScanAgentPropertiesManager extends PropertiesManager {

    private static PropertiesConfiguration properties; // this is a single-threaded environment right?

    private static Logger log = Logger.getLogger(ScanAgentPropertiesManager.class);

    private static final int
            POLL_INTERVAL_DEFAULT = 5,
            MAX_TASKS_DEFAULT = 10;

    public static final String URL_KEY = "scanagent.threadFixServerUrl",
            API_KEY = "scanagent.threadFixApiKey",
            FILE_NAME = "scanagent.properties",
            WORKING_DIRECTORY_KEY = "scanagent.baseWorkDir",
            POLL_INTERVAL_KEY = "scanagent.pollInterval",
            MAX_TASKS_KEY = "scanagent.maxTasks",
            DEFAULT_URL = "http://localhost:8080/threadfix/rest";

    public static String getFromProperties(ScannerType type) {
        String key = type.getShortName() + ".scanName";
        return readProperty(key);
    }

    public static int getPollInterval() {
        return getInt(POLL_INTERVAL_KEY, POLL_INTERVAL_DEFAULT);
    }

    public static int getMaxTasks() {
        return getInt(MAX_TASKS_KEY, MAX_TASKS_DEFAULT);
    }

    private static int getInt(String key, int defaultValue) {
        String pollIntervalString = readProperty(key);

        int pollInterval = defaultValue;

        if (pollIntervalString != null && pollIntervalString.matches("^[0-9]+$")) {
            pollInterval = Integer.valueOf(pollIntervalString);
        }

        if (pollInterval < 1) {
            pollInterval = defaultValue;
        }

        return pollInterval;
    }

    public static void saveWorkDirectory(String workDirectory) {
        writeProperty(WORKING_DIRECTORY_KEY, workDirectory);
    }

    public static String getWorkingDirectory() {
        return readProperty(WORKING_DIRECTORY_KEY);
    }

    public static void saveUrl(String url) {
        writeProperty(URL_KEY, url);
    }

    @Override
    public String getUrl() {
        return getUrlStatic();
    }

    public static String getUrlStatic() {
        String url = readProperty(URL_KEY);
        return url == null ? DEFAULT_URL : url;
    }

    public static void saveKey(String apiKey) {
        writeProperty(API_KEY, apiKey);
    }

    @Override
    public String getKey() {
        return getKeyStatic();
    }

    public static String getKeyStatic() {
        return readProperty(API_KEY);
    }

    public static String readProperty(String propName) {
        if (properties == null) {
            readProperties();
            if (properties == null) {
                properties = getPropertiesFile();
            }
        }

        Object property = properties.getProperty(propName);

        return property == null ? null : property.toString();
    }

    public static void writeProperty(String propName, String propValue) {
        readProperties();
        properties.setProperty(propName, propValue);
    }

    @NotNull
    public static PropertiesConfiguration getPropertiesFile() {
        try {
            File file = new File(ScanAgentPropertiesManager.FILE_NAME);

            if (!file.exists()) {
                if (file.createNewFile()) {
                    log.info("Created new properties file.");
                } else {
                    String message = "Failed to create a new properties file.";
                    log.info(message);
                    throw new ScanAgentConfigurationUnavailableException(message);
                }
            }

            PropertiesConfiguration config = new PropertiesConfiguration(file);
            config.setAutoSave(true);
            return config;
        } catch (ConfigurationException | IOException e) {
            String message = "Problems reading configuration: " + e.getMessage();
            log.error(message, e);
            throw new ScanAgentConfigurationUnavailableException(message, e);
        }
    }

    private static void readProperties() {
        if (properties == null) {
            properties = getPropertiesFile();
        }
    }
}
