package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

/**
 * Created by mac on 9/23/13.
 */
public class ThreadFixPropertiesManager {

    private static final Logger logger = Logger.getLogger(ThreadFixPropertiesManager.class);

    private static final String
            FILE_NAME = "threadfix.properties",
            API_KEY_KEY = "key",
            URL_KEY = "url",
            APP_ID_KEY = "application-id",
            SAVE_MESSAGE = "Saving ZAP properties.";

    public static String getKey() {
        String key = getProperties().getProperty(API_KEY_KEY);
        logger.info("returning api key " + key);
        return key;
    }

    public static String getAppId() {
        String id = getProperties().getProperty(APP_ID_KEY);
        return id;
    }

    public static String getUrl() {
        String url = getProperties().getProperty(URL_KEY);
        if (url == null) {
            url = "http://localhost:8080/threadfix/rest";
        }
        logger.info("returning url " + url);
        return url;
    }

    public static void setKeyAndUrl(String newKey, String newUrl) {
        Properties properties = getProperties();
        properties.setProperty(API_KEY_KEY, newKey);
        properties.setProperty(URL_KEY, newUrl);
        saveProperties(properties);
    }

    public static void setAppId(String appId) {
        Properties properties = getProperties();
        properties.setProperty(APP_ID_KEY, appId);
        saveProperties(properties);
    }

    private static Properties getProperties() {
        Properties properties = new Properties();

        File file = new File(FILE_NAME);

        logger.info("Properties file is at " + file.getAbsolutePath());

        if (!file.exists()) {
            try {
                logger.info("Creating new file.");
                file.createNewFile();
            } catch (IOException e) {
                logger.warn("Failed trying to initialize properties file.", e);
            }
        }

        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                properties.load(reader);
                logger.info("Successfully loaded properties.");
            } catch (IOException e) {
                logger.warn("Failed attempting to load from properties file.", e);
            }
        } else {
            logger.warn("File didn't exist");
        }

        return properties;
    }

    private static void saveProperties(Properties properties) {
        try (FileWriter writer = new FileWriter(new File(FILE_NAME))) {
            properties.store(writer, SAVE_MESSAGE);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
        }
    }

}
