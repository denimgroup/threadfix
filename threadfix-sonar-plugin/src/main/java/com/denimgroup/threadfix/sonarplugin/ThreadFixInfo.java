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

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.remote.PluginClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixInfo {

    enum Mode {
        SERVER, LOCAL
    }

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixInfo.class);

    private String url, apiKey, applicationName, applicationId;

    private String localFiles, localDirectories;

    private Set<String> files = set();

    private Mode mode = Mode.SERVER;

    public ThreadFixInfo(Map<String, String> properties) {
        this.url = properties.get("threadfix.url");
        this.apiKey = properties.get("threadfix.apiKey");
        this.applicationName = properties.get("threadfix.applicationName");
        this.applicationId = properties.get("threadfix.applicationId");

        this.localDirectories = properties.get("threadfix.localDirectories");
        this.localFiles = properties.get("threadfix.localFiles");

        List<String> errors = getErrors();

        if (errors.isEmpty() && mode == Mode.SERVER && this.applicationId == null) {
            this.applicationId = getApplicationId(this);
        }
    }

    private String getApplicationId(ThreadFixInfo info) {
        PluginClient client = new PluginClient(info.getUrl(), info.getApiKey());

        Application.Info[] threadFixApplications = client.getThreadFixApplications();

        LOG.debug("Looking for ThreadFix applications.");

        String returnId = null;

        for (Application.Info threadFixApplication : threadFixApplications) {
            String applicationName = threadFixApplication.applicationName;

            String id = threadFixApplication.getApplicationId();

            LOG.debug("Application name " + applicationName + " has ID " + id);

            if (info.getApplicationName().equals(threadFixApplication.getApplicationName())) {
                LOG.debug("Found match: " + info.getApplicationName() + ", id=" + id);
                returnId = id;
            }
        }

        if (threadFixApplications.length == 0) {
            LOG.error("No ThreadFix applications found, please set one up in ThreadFix and try again.");
        }

        return returnId;
    }

    public boolean valid() {
        return getErrors().isEmpty();
    }

    public List<String> getErrors() {

        LOG.info("Checking ThreadFix configuration.");

        List<String> errors = new ArrayList<>();

        boolean emptyLocal = allEmpty(localDirectories, localFiles),
                emptyServer = allEmpty(url, apiKey, applicationName, applicationId);

        if (emptyLocal && emptyServer) {
            errors.add("No ThreadFix configuration found.");
            errors.add("Use the properties threadfix.localFiles or threadfix.localDirectories to use local scans");
            errors.add("Use the properties threadfix.url, threadfix.apiKey, and either threadfix.applicationName or threadfix.applicationId to use a ThreadFix server instance");
        } else if (emptyLocal) {
            errors.addAll(testServer());
        } else if (emptyServer) {
            errors.addAll(testLocal());
            mode = Mode.LOCAL;
        } else {
            LOG.info("Both server and local configurations found.");

            List<String>
                    localErrors  = testLocal(),
                    serverErrors = testServer();

            if (localErrors.isEmpty() && serverErrors.isEmpty()) {
                LOG.info("Both server and local configurations were valid. ");
                LOG.info("Defaulting to server, please remove server configuration to use local files.");
            } else if (localErrors.isEmpty()) {
                for (String serverError : serverErrors) {
                    LOG.debug(serverError);
                }
                LOG.info("Incomplete server configuration. Using local settings.");
                mode = Mode.LOCAL;
            } else if (serverErrors.isEmpty()) {
                for (String localError : localErrors) {
                    LOG.debug(localError);
                }
                LOG.info("There were errors with the local configuration, using server configuration.");
            } else {
                errors.addAll(serverErrors);
                errors.addAll(localErrors);
            }
        }

        return errors;
    }

    private List<String> testServer() {
        List<String> errors = list();

        if (url == null) {
            errors.add("ThreadFix URL is null, please set the property threadfix.url");
        }

        if (apiKey == null) {
            errors.add("ThreadFix API Key is null, please set the property threadfix.apiKey");
        }

        if (applicationName == null && applicationId == null) {
            errors.add("ThreadFix Application name and ID are null, please set the property threadfix.applicationName or the property threadfix.applicationId");
        }

        // TODO make a request here

        return errors;
    }

    // tons of validation code
    private List<String> testLocal() {

        List<String> errors = list();

        if (localDirectories != null) {
            String[] splitDirectories = localDirectories.split(",");

            for (String splitDirectory : splitDirectories) {
                File directory = new File(splitDirectory.trim());

                if (!directory.exists()) {
                    errors.add("\"" + splitDirectory + "\" wasn't found.");
                } else if (!directory.isDirectory()) {
                    errors.add("\"" + splitDirectory + "\" isn't a directory.");
                } else {
                    File[] files = directory.listFiles();
                    if (files == null) {
                        errors.add("No files found in directory " + splitDirectory);
                        continue;
                    }
                    
                    for (File file : files) {
                        if (file.isFile()) {
                            this.files.add(file.getAbsolutePath());
                        }
                    }
                }
            }
        }

        if (localFiles != null) {
            String[] splitFiles = localFiles.split(",");

            for (String splitFile : splitFiles) {
                File file = new File(splitFile.trim());

                if (!file.exists()) {
                    errors.add("\"" + splitFile + "\" wasn't found.");
                } else if (!file.isFile()) {
                    errors.add("\"" + splitFile + "\" isn't a file.");
                } else {
                    this.files.add(file.getAbsolutePath());
                }
            }
        }

        if (errors.isEmpty() && this.files.isEmpty()) {
            errors.add("No files found.");
        }

        return errors;
    }

    private boolean allEmpty(String... properties) {
        for (String property : properties) {
            if (property != null && !property.equals("")) {
                return false;
            }
        }
        return true;
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
}
