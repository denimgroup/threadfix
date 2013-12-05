package com.denimgroup.threadfix.plugins.intellij.properties;

import com.intellij.ide.util.PropertiesComponent;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

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

    public static Set<String> getApplicationIds() {
        return toSet(readFromProperties(APPLICATION_KEY));
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

    public static void setApplicationKey(Set<String> applicationIds) {
        writeToProperties(APPLICATION_KEY, toString(applicationIds));
    }

    private static String toString(Set<String> input) {
        StringBuilder builder = new StringBuilder();

        for (String string : input) {
            builder.append(string).append(",");
        }

        if (builder.length() > 0) {
            // kill last comma
            builder.setLength(builder.length() - 1);
        }

        return builder.toString();
    }

    private static Set<String> toSet(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new HashSet<String>();
        } else {
            return new HashSet<String>(Arrays.asList(input.split(",")));
        }
    }
}
