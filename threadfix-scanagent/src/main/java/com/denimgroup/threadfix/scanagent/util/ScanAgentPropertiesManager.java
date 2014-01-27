package com.denimgroup.threadfix.scanagent.util;

import com.denimgroup.threadfix.properties.PropertiesManager;

import java.io.*;
import java.util.Properties;

/**
 * Created by mac on 1/27/14.
 */
public class ScanAgentPropertiesManager extends PropertiesManager {

    private static Properties properties; // this is a single-threaded environment right?

    public static final String URL_KEY = "scanagent.threadFixServerUrl",
            API_KEY = "scanagent.threadFixApiKey",
            FILE_NAME = "scanagent.properties",
            WORKING_DIRECTORY_KEY = "scanagent.baseWorkDir",
            DEFAULT_URL = "http://localhost:8080/threadfix/rest";


    public static String getUrlStatic() {
        String url = getProperty(URL_KEY);
        return url == null ? DEFAULT_URL : url;
    }

    public static void saveKey(String apiKey) {
        writeProperty(API_KEY, apiKey);
    }

    public static void saveUrl(String url) {
        writeProperty(URL_KEY, url);
    }

    public static void saveWorkDirectory(String workDirectory) {
        writeProperty(WORKING_DIRECTORY_KEY, workDirectory);
    }

    @Override
    public String getUrl() {
        return getUrlStatic();
    }

    @Override
    public String getKey() {
        return getKeyStatic();
    }

    public static String getKeyStatic() {
        return getProperty(API_KEY);
    }

    private static String getProperty(String propName) {
        if (properties == null) {
            readProperties();
            if (properties == null) {
                properties = new Properties();
                writeProperties();
            }
        }

        return properties.getProperty(propName);
    }

    public static void writeProperty(String propName, String propValue) {
        readProperties();
        properties.setProperty(propName, propValue);
        writeProperties();
    }

    private static void readProperties() {
        if (properties == null) {
            properties = new Properties();
        }

        File propertiesFile = new File(FILE_NAME);

        try (FileInputStream in = new FileInputStream(propertiesFile)) {
            if (!propertiesFile.exists()) {
                propertiesFile.createNewFile();
            }

            if (properties == null) {
                properties = new Properties();
            }
            properties.load(in);
        } catch (FileNotFoundException e) {
            try {
                System.out.println("Cannot find ThreadFix properties file: " +
                        propertiesFile.getCanonicalPath());
            } catch(IOException ioe) {
                System.out.println("Cannot find ThreadFix properties file 'threadfix.properties' " +
                        "IOException encountered while trying.");
                ioe.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeProperties() {
        try (FileOutputStream out = new FileOutputStream(FILE_NAME)) {
            properties.store(out, "Writing.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
