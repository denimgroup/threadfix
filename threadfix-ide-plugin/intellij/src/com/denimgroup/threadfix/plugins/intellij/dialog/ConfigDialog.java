package com.denimgroup.threadfix.plugins.intellij.dialog;

import com.denimgroup.threadfix.plugins.intellij.properties.PropertiesManager;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.InputValidator;
import com.intellij.openapi.ui.Messages;

import java.net.MalformedURLException;
import java.net.URL;

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

        String url = getUrl(e), apiKey = null, apps = null;

        if (url != null) {
            apiKey = getApiKey(e);

            if (isValid(url, apiKey)) {
                PropertiesManager.setApiKey(apiKey);
                PropertiesManager.setUrl(url);

                apps = getApplications(e);

                PropertiesManager.setApplicationKey(apps);
            }
        }

        return url != null && apiKey != null && apps != null;
    }

    private static String getUrl(AnActionEvent e) {

        String configuredUrl = PropertiesManager.getUrl();

        if (configuredUrl == null) {
            configuredUrl = "http://localhost:8080/threadfix/rest";
        }

        Project project = e.getData(PlatformDataKeys.PROJECT);
        return Messages.showInputDialog(project,
                "What is your ThreadFix URL?",
                "ThreadFix URL",
                Messages.getInformationIcon(),
                configuredUrl,
                UrlValidator.INSTANCE);
    }

    private static String getApiKey(AnActionEvent e) {
        String configuredApiKey = PropertiesManager.getApiKey();

        Project project = e.getData(PlatformDataKeys.PROJECT);
        return Messages.showInputDialog(project,
                "What is your ThreadFix API Key?",
                "ThreadFix API Key",
                Messages.getInformationIcon(),
                configuredApiKey,
                null);
    }

    private static String getApplications(AnActionEvent e) {
        String configuredApiKey = PropertiesManager.getApplicationKey();

        Project project = e.getData(PlatformDataKeys.PROJECT);
        return Messages.showInputDialog(project,
                "Which ThreadFix apps would you like to import data from?",
                "ThreadFix Applications",
                Messages.getInformationIcon(),
                configuredApiKey,
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
                        url.getPath() != null && !url.getPath().isEmpty();
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
        // TODO check with the REST interface
        return url != null && !url.isEmpty() && apiKey != null && !apiKey.isEmpty();
    }

}
