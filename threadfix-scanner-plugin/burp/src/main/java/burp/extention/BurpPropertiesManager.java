////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package burp.extention;


import com.denimgroup.threadfix.properties.PropertiesManager;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

public class BurpPropertiesManager extends PropertiesManager {

    private static final String
            FILE_NAME = "threadfix.properties",
            API_KEY_KEY = "key",
            THREADFIX_URL_KEY = "url",
            TARGET_URL_KEY = "target-url",
            APP_ID_KEY = "application-id",
            SAVE_MESSAGE = "Saving BURP properties.";

    public static String getKeyStatic() {
        return getProperties().getProperty(API_KEY_KEY);
    }

    public static String getAppId() {
        return getProperties().getProperty(APP_ID_KEY);
    }

    @Override
    public String getUrl() {
        return getUrlStatic();
    }

    @Override
    public String getKey() {
        return getKeyStatic();
    }

    public static String getUrlStatic() {
        String url = getProperties().getProperty(THREADFIX_URL_KEY);
        if (url == null) {
            url = "http://localhost:8080/threadfix/rest";
        }
        return url;
    }

    public static String getTargetUrl() {
        return getProperties().getProperty(TARGET_URL_KEY);
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


        try {
            if (!file.exists()) {
                file.createNewFile();
            }

            if (file.exists()) {
                try (FileReader reader = new FileReader(file)) {
                    properties.load(reader);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return properties;
    }

    private static void saveProperties(Properties properties) {
        try (FileWriter writer = new FileWriter(new File(FILE_NAME))) {
            properties.store(writer, SAVE_MESSAGE);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
