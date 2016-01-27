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

import com.denimgroup.threadfix.properties.PropertiesManager;
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
public class IntelliJPropertiesManager extends PropertiesManager {

    public static final IntelliJPropertiesManager INSTANCE = new IntelliJPropertiesManager();

    private IntelliJPropertiesManager(){}

    private static final String
            URL_KEY = "url",
            API_KEY = "key",
            APPLICATION_KEY = "appKey",
            LAST_RESPONSE_KEY = "lastResponse",
            COMMA = ",";

    private static String readFromProperties(String key) {
        return PropertiesComponent.getInstance().getValue(key);
    }

    public String getLastResponse() {
        return readFromProperties(LAST_RESPONSE_KEY);
    }

    @Override
    public String getUrl() {
        return readFromProperties(URL_KEY);
    }

    @Override
    public String getKey(){
        return readFromProperties(API_KEY);
    }

    public Set<String> getApplicationIds() {
        return toSet(readFromProperties(APPLICATION_KEY));
    }

    private void writeToProperties(String key, String value) {
        PropertiesComponent.getInstance().setValue(key, value);
    }

    @Override
    public void setUrl(String url) {
        writeToProperties(URL_KEY, url);
    }

    @Override
    public void setKey(String apiKey) {
        writeToProperties(API_KEY, apiKey);
    }

    public void setLastResponse(String lastResponse) {
        writeToProperties(LAST_RESPONSE_KEY, lastResponse);
    }

    public void setApplicationKey(Set<String> applicationIds) {
        writeToProperties(APPLICATION_KEY, toString(applicationIds));
    }

    private String toString(Set<String> input) {
        StringBuilder builder = new StringBuilder();

        for (String string : input) {
            builder.append(string).append(COMMA);
        }

        if (builder.length() > 0) {
            // kill last comma
            builder.setLength(builder.length() - 1);
        }

        return builder.toString();
    }

    private Set<String> toSet(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new HashSet<String>();
        } else {
            return new HashSet<String>(Arrays.asList(input.split(COMMA)));
        }
    }
}
