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
package com.denimgroup.threadfix.sonarplugin.configuration;

import com.denimgroup.threadfix.sonarplugin.util.ThreadFixTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixInfo {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixInfo.class);

    String url, apiKey, applicationName, applicationId;

    String localFiles, localDirectories;
    String defaultFile;

    Set<String> files = set();

    Mode mode = Mode.SERVER;
    
    final List<String> errors;

    public ThreadFixInfo(Map<String, String> properties) {
        this.url = properties.get("threadfix.url");
        this.apiKey = properties.get("threadfix.apiKey");
        this.applicationName = properties.get("threadfix.applicationName");
        this.applicationId = properties.get("threadfix.applicationId");
        this.defaultFile = properties.get("threadfix.defaultFile");

        this.localDirectories = properties.get("threadfix.localDirectories");
        this.localFiles = properties.get("threadfix.localFiles");

        errors = ConfigurationCheck.getErrors(this);

        if (errors.isEmpty() && mode == Mode.SERVER && this.applicationId == null) {
            this.applicationId = ThreadFixTools.getApplicationId(this);
        }
    }

    public boolean valid() {
        return errors.isEmpty();
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

    public String getApplicationId() {
        return applicationId;
    }

    public Set<String> getFiles() {
        return files;
    }

    public Mode getMode() {
        return mode;
    }

    public List<String> getErrors() {
        return errors;
    }

    public String getDefaultFile() {
        return defaultFile == null ? "threadfix.xml" : defaultFile;
    }
}
