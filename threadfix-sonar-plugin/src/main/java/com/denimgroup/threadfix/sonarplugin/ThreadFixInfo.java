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
package com.denimgroup.threadfix.sonarplugin;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixInfo {

    private String url, apiKey, applicationName;

    public ThreadFixInfo(Map<String, String> properties) {
        this.url = properties.get("threadfix.url");
        this.apiKey = properties.get("threadfix.apiKey");
        this.applicationName = properties.get("threadfix.applicationName");
    }

    public boolean valid() {
        return getErrors().isEmpty();
    }

    public List<String> getErrors() {
        List<String> errors = new ArrayList<>();

        if (url == null) {
            errors.add("ThreadFix URL is null, please set the property threadfix.url");
        }

        if (apiKey == null) {
            errors.add("ThreadFix API Key is null, please set the property threadfix.apiKey");
        }

        if (applicationName == null) {
            errors.add("ThreadFix Application name is null, please set the property threadfix.applicationName");
        }

        return errors;
    }

    public String getUrl() {
        return url;
    }

    public String getApiKey() {
        return apiKey;
    }

    public String getApplicationName() {
        return applicationName;
    }
}
