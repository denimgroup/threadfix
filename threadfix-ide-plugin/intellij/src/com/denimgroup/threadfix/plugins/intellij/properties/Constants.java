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
package com.denimgroup.threadfix.plugins.intellij.properties;

public interface Constants {

    public static final String
            DEFAULT_URL = "http://localhost:8080/threadfix/rest",
            AUTHENTICATION_FAIL_STRING = "Authentication fail",
            APP_LOOKUP_FAILURE_STRING = "Couldn't find the application with ID 0",
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
            CWE_ADDRESS_START = "http://cwe.mitre.org/data/definitions/";

}
