////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package org.zaproxy.zap.extension.threadfix;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

import org.parosproxy.paros.Constant;

/**
 * Created by mac on 9/23/13.
 */
public class ZapPropertiesManager extends AbstractZapPropertiesManager {

    private static final Logger logger = Logger.getLogger(ZapPropertiesManager.class);

    public static final ZapPropertiesManager INSTANCE = new ZapPropertiesManager();

    private ZapPropertiesManager(){}

    private static final String
            FILE_NAME = "threadfix.properties",
            API_KEY_KEY = "key",
            URL_KEY = "url",
            APP_ID_KEY = "application-id",
            SOURCE_FOLDER_KEY = "source-folder",
            SAVE_MESSAGE = "Saving ZAP properties.";

    @Override
    public String getKey() {
        String key = getProperties().getProperty(API_KEY_KEY);
        logger.info("returning api key " + key);
        return key;
    }

    @Override
    public String getAppId() {
        return getProperties().getProperty(APP_ID_KEY);
    }

    @Override
    public String getUrl() {
        String url = getProperties().getProperty(URL_KEY);
        if (url == null) {
            url = "http://localhost:8080/threadfix/rest";
        }
        logger.info("returning url " + url);
        return url;
    }

    public String getSourceFolder() {
        String sourceFolder = getProperties().getProperty(SOURCE_FOLDER_KEY);
        logger.info("returning source code folder " + sourceFolder);
        return sourceFolder;
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

    public static void setSourceFolder(String sourceFolder) {
        Properties properties = getProperties();
        properties.setProperty(SOURCE_FOLDER_KEY, sourceFolder);
        saveProperties(properties);
    }

    private static Properties getProperties() {
        Properties properties = new Properties();

        File file = new File(Constant.getZapHome(), FILE_NAME);

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
        try (FileWriter writer = new FileWriter(new File(Constant.getZapHome(), FILE_NAME))) {
            properties.store(writer, SAVE_MESSAGE);
        } catch (IOException e) {
            logger.warn(e.getMessage(), e);
        }
    }

}
