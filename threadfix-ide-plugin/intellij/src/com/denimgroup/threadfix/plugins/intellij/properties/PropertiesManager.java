package com.denimgroup.threadfix.plugins.intellij.properties;

import com.intellij.ide.util.PropertiesComponent;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/3/13
 * Time: 2:38 PM
 * To change this template use File | Settings | File Templates.
 */
public class PropertiesManager {

    private static String URL = "url", API_KEY = "key", APPLICATION_KEY = "appKey";

    private PropertiesManager(){}

    private static String readFromProperties(String key) {
        return PropertiesComponent.getInstance().getValue(key);
    }

    public static String getUrl() {
        return readFromProperties(URL);
    }

    public static String getApiKey(){
        return readFromProperties(API_KEY);
    }

    public static String getApplicationKey() {
        return readFromProperties(APPLICATION_KEY);
    }


    private static void writeToProperties(String key, String value) {
        PropertiesComponent.getInstance().setValue(key, value);
    }

    public static void setUrl(String url) {
        writeToProperties(URL, url);
    }

    public static void setApiKey(String apiKey) {
        writeToProperties(API_KEY, apiKey);
    }

    public static void setApplicationKey(String applicationKey) {
        writeToProperties(APPLICATION_KEY, applicationKey);
    }




}
