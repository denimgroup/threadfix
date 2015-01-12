////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.denimgroup.threadfix.plugins.intellij.properties.Constants;
import com.denimgroup.threadfix.plugins.intellij.properties.IntelliJPropertiesManager;
import com.denimgroup.threadfix.plugins.intellij.rest.RestUtils;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.InputValidator;
import com.intellij.openapi.ui.Messages;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/3/13
 * Time: 2:37 PM
 * To change this template use File | Settings | File Templates.
 */
public class ConfigDialog {

    private ConfigDialog(){}

    public static boolean show(AnActionEvent e) {

        String url = getValidUrl(e), apiKey = null;
        Set<String> apps = null;

        if (url != null) {
            apiKey = getValidApiKey(e, url);

            if (apiKey != null) {
                IntelliJPropertiesManager.INSTANCE.setKey(apiKey);
                IntelliJPropertiesManager.INSTANCE.setUrl(url);

                apps = ApplicationsDialog.getApplications();

                IntelliJPropertiesManager.INSTANCE.setApplicationKey(apps);
            }
        }

        return url != null && apiKey != null && apps != null;
    }

    private static String getValidUrl(AnActionEvent e) {
        String configuredUrl = IntelliJPropertiesManager.INSTANCE.getUrl();

        if (configuredUrl == null) {
            configuredUrl = Constants.DEFAULT_URL;
        }

        String url = getUrl(e, Constants.URL_CONFIG_MESSAGE_1, configuredUrl);

        while (url != null && !isValidUrl(url)) {
            url = getUrl(e, Constants.URL_CONFIG_MESSAGE_2, url);
        }

        return url;
    }

    private static String getUrl(AnActionEvent e, String text, String url) {
        Project project = e.getData(PlatformDataKeys.PROJECT);
        return Messages.showInputDialog(project,
                text,
                Constants.URL_CONFIG_TITLE,
                Messages.getInformationIcon(),
                url,
                UrlValidator.INSTANCE);
    }

    private static boolean isValidUrl(String url) {
        RestResponse<Object> response = RestUtils.test(url);
        return !response.success &&
                response.responseCode == 200 &&
                response.message.trim().startsWith(Constants.AUTHENTICATION_FAIL_STRING);
    }

    private static String getValidApiKey(AnActionEvent e, String url) {
        String propertiesKey = IntelliJPropertiesManager.INSTANCE.getKey();

        String keyInput = getApiKey(e, Constants.API_KEY_MESSAGE_1, propertiesKey);

        while (keyInput != null && !isValid(url, keyInput)) {
            keyInput = getApiKey(e, Constants.API_KEY_MESSAGE_2, keyInput);
        }

        return keyInput;
    }

    private static String getApiKey(AnActionEvent e, String message, String key) {
        Project project = e.getData(PlatformDataKeys.PROJECT);
        return Messages.showInputDialog(project,
                message,
                Constants.API_KEY_TITLE,
                Messages.getInformationIcon(),
                key,
                null);
    }

    private static class UrlValidator implements InputValidator {

        public static final UrlValidator INSTANCE = new UrlValidator();

        private UrlValidator(){}

        @Override
        public boolean checkInput(String s) {
            try {
                URL url = new URL(s);
                return url.getHost() != null && !url.getHost().isEmpty() &&
                        url.getPath() != null && url.getPath().endsWith(Constants.REST_URL_EXTENSION_STRING);
            } catch (MalformedURLException e) {
                return false;
            }
        }

        @Override
        public boolean canClose(String s) {
            return true;
        }
    }

    private static boolean isValid(String url, String apiKey) {
        RestResponse response = RestUtils.test(url, apiKey);
        return !response.success &&
                response.responseCode == 200 &&
                response.message.startsWith(Constants.APP_LOOKUP_FAILURE_STRING);
    }
}
