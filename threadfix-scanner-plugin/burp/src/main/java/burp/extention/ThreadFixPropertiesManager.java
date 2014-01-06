package burp.extention;


import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

/**
 * Created by mac on 9/23/13.
 */
public class ThreadFixPropertiesManager {

    private static final String
            FILE_NAME = "threadfix.properties",
            API_KEY_KEY = "key",
            THREADFIX_URL_KEY = "url",
            TARGET_URL_KEY = "target-url",
            APP_ID_KEY = "application-id",
            SAVE_MESSAGE = "Saving BURP properties.";

    public static String getKey() {
        String key = getProperties().getProperty(API_KEY_KEY);
        return key;
    }

    public static String getAppId() {
        String id = getProperties().getProperty(APP_ID_KEY);
        return id;
    }

    public static String getUrl() {
        String url = getProperties().getProperty(THREADFIX_URL_KEY);
        if (url == null) {
            url = "http://localhost:8080/threadfix/rest";
        }
        return url;
    }

    public static String getTargetUrl() {
        String url = getProperties().getProperty(TARGET_URL_KEY);
        return url;
    }

    public static void setKeyAndUrl(String newKey, String newUrl) {
        Properties properties = getProperties();
        properties.setProperty(API_KEY_KEY, newKey);
        properties.setProperty(THREADFIX_URL_KEY, newUrl);
        saveProperties(properties);
    }

    public static void setTargetUrl(String targetUrl) {
        Properties properties = getProperties();
        properties.setProperty(TARGET_URL_KEY, targetUrl);
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


        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
            }
        }

        if (file.exists()) {
            try (FileReader reader = new FileReader(file)) {
                properties.load(reader);
            } catch (IOException e) {
            }
        } else {
        }

        return properties;
    }

    private static void saveProperties(Properties properties) {
        try (FileWriter writer = new FileWriter(new File(FILE_NAME))) {
            properties.store(writer, SAVE_MESSAGE);
        } catch (IOException e) {
        }
    }

}
