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

package burp.extention;


import burp.IBurpExtenderCallbacks;
import com.denimgroup.threadfix.properties.PropertiesManager;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class BurpPropertiesManager extends PropertiesManager {
    private static BurpPropertiesManager instance = null;

    public static final String
            API_KEY_KEY = "threadfix.key",
            THREADFIX_URL_KEY = "threadfix.url",
            APP_ID_KEY = "threadfix.application-id",
            TARGET_URL_KEY = "threadfix.target-url",
            SOURCE_FOLDER_KEY = "threadfix.source-folder";

    private static final Map<String, String> defaultPropertyValues = new HashMap<String, String>();
    static {
        defaultPropertyValues.put(THREADFIX_URL_KEY, "http://localhost:8080/threadfix/rest");
    }

    private static IBurpExtenderCallbacks callbacks;
    private static Properties properties = new Properties();
    private static boolean hasChanges = false;

    private BurpPropertiesManager(IBurpExtenderCallbacks callbacks) {
        super();
        this.callbacks = callbacks;
    }

    public static BurpPropertiesManager generateBurpPropertiesManager(IBurpExtenderCallbacks callbacks) {
        if (instance == null) {
            instance = new BurpPropertiesManager(callbacks);
            return instance;
        }
        throw new RuntimeException("A BurpPropertiesManager already exists.");
    }

    public static BurpPropertiesManager getBurpPropertiesManager() {
        return instance;
    }

    public String getPropertyValue(String key) {
        String value = properties.getProperty(key);
        if (value == null) {
            value = callbacks.loadExtensionSetting(key);
        }
        if ((value == null) || (value.trim().equals(""))) {
            return defaultPropertyValues.get(key);
        }
        return value;
    }

    public void setPropertyValue(String key, String value) {
        properties.setProperty(key, value);
        hasChanges = true;
    }

    public void saveProperties() {
        if (hasChanges) {
            for (String key : properties.stringPropertyNames()) {
                String newValue = properties.getProperty(key);
                String oldValue = callbacks.loadExtensionSetting(key);
                if (!newValue.equals(oldValue)) {
                    callbacks.saveExtensionSetting(key, newValue);
                    properties.remove(key);
                }
            }
            hasChanges = false;
        }
    }

    @Override
    public String getKey() {
        return getPropertyValue(API_KEY_KEY);
    }

    @Override
    public void setKey(String newKey) {
        setPropertyValue(API_KEY_KEY, newKey);
    }

    @Override
    public void setMemoryKey(String newKey) {
        setKey(newKey);
    }

    @Override
    public String getUrl() {
        return getPropertyValue(THREADFIX_URL_KEY);
    }

    @Override
    public void setUrl(String newUrl) {
        setPropertyValue(THREADFIX_URL_KEY, newUrl);
    }

    @Override
    public void setMemoryUrl(String newUrl) {
        setUrl(newUrl);
    }

    public String getAppId() {
        return getPropertyValue(APP_ID_KEY);
    }

    public void setAppId(String newAppId) {
        setPropertyValue(APP_ID_KEY, newAppId);
    }

    public String getTargetUrl() {
        return getPropertyValue(TARGET_URL_KEY);
    }

    public void setTargetUrl(String newTargetUrl) {
        setPropertyValue(TARGET_URL_KEY, newTargetUrl);
    }

    public String getSourceFolder() {
        return getPropertyValue(SOURCE_FOLDER_KEY);
    }

    public void setSourceFolder(String newSourceFolder) {
        setPropertyValue(SOURCE_FOLDER_KEY, newSourceFolder);
    }
}
