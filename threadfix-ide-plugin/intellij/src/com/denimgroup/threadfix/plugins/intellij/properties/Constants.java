package com.denimgroup.threadfix.plugins.intellij.properties;

public interface Constants {

    public static final String
            DEFAULT_URL = "http://localhost:8080/threadfix/rest",
            AUTHENTICATION_FAIL_STRING = "Authentication fail",
            REST_FAILURE_STRING = "failure",
            REST_URL_EXTENSION_STRING = "/rest",
            API_KEY_TITLE = "ThreadFix API Key",
            API_KEY_MESSAGE_1 = "What is your ThreadFix API Key?",
            API_KEY_MESSAGE_2 = "Invalid API Key, please try again. API Keys can be found under the Configuration (the cog) / API Keys.",
            URL_CONFIG_TITLE = "ThreadFix URL",
            URL_CONFIG_MESSAGE_1 = "What is your ThreadFix URL?",
            URL_CONFIG_MESSAGE_2 = "That was an invalid URL, please try again.",
            CLEAR_MARKERS_MESSAGE = "Clearing ThreadFix markers.",
            IMPORT_MARKERS_MESSAGE = "Importing ThreadFix markers.",
            SHOW_TOOL_WINDOW_MESSAGE = "Showing ThreadFix Tool Window",
            CANCEL_PRESSED_MESSAGE = "Cancel pressed.",
            TOOL_WINDOW_NAME = "ThreadFix",
            APPLICATION_SELECTION_TITLE = "ThreadFix Applications to Import",
            THREADFIX_ICON_NAME = "/icons/DG_logo_mark_13x13.png",
            MARKERS_URL_SEGMENT = "/code/markers/",
            APPLICATIONS_URL_SEGMENT = "/code/applications/",
            API_KEY_QUERY_START = "?apiKey=";

}
