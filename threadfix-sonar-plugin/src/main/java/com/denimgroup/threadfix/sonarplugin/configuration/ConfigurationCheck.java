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
package com.denimgroup.threadfix.sonarplugin.configuration;

import com.denimgroup.threadfix.importer.util.SpringConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;

import java.io.File;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 2/4/15.
 */
public class ConfigurationCheck {

    private static final Logger LOG = LoggerFactory.getLogger(ConfigurationCheck.class);

    private ConfigurationCheck() {}

    ThreadFixInfo info;

    // This main method will fail if Spring has an invalid configuration
    public static void main(String[] args) {
        AnnotationConfigApplicationContext context = SpringConfiguration.getContext();

        SpringConfiguration bean = context.getBean(SpringConfiguration.class);

        System.out.println(bean);
    }

    public static List<String> getErrors(ThreadFixInfo info) {
        ConfigurationCheck check = new ConfigurationCheck();
        check.info = info;

        return check.getErrors();
    }

    private List<String> getErrors() {

        LOG.info("Checking ThreadFix configuration.");

        List<String> errors = list();

        boolean emptyLocal = allEmpty(info.localDirectories, info.localFiles),
                emptyServer = allEmpty(info.url, info.apiKey, info.applicationName, info.applicationId);

        if (emptyLocal && emptyServer) {
            errors.add("No ThreadFix configuration found.");
            errors.add("Use the properties threadfix.localFiles or threadfix.localDirectories to use local scans");
            errors.add("Use the properties threadfix.url, threadfix.apiKey, and either threadfix.applicationName or threadfix.applicationId to use a ThreadFix server instance");
        } else if (emptyLocal) {
            errors.addAll(testServer());
        } else if (emptyServer) {
            errors.addAll(testLocal());
            info.mode = Mode.LOCAL;
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
                info.mode = Mode.LOCAL;
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

        if (info.url == null) {
            errors.add("ThreadFix URL is null, please set the property threadfix.url");
        }

        if (info.apiKey == null) {
            errors.add("ThreadFix API Key is null, please set the property threadfix.apiKey");
        }

        if (info.applicationName == null && info.applicationId == null) {
            errors.add("ThreadFix Application name and ID are null, please set the property threadfix.applicationName or the property threadfix.applicationId");
        }

        // TODO make a request here

        return errors;
    }

    // tons of validation code
    private List<String> testLocal() {

        List<String> errors = list();

        if (info.localDirectories != null) {
            String[] splitDirectories = info.localDirectories.split(",");

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
                            info.files.add(file.getAbsolutePath());
                        }
                    }
                }
            }
        }

        if (info.localFiles != null) {
            String[] splitFiles = info.localFiles.split(",");

            for (String splitFile : splitFiles) {
                File file = new File(splitFile.trim());

                if (!file.exists()) {
                    errors.add("\"" + splitFile + "\" wasn't found.");
                } else if (!file.isFile()) {
                    errors.add("\"" + splitFile + "\" isn't a file.");
                } else {
                    info.files.add(file.getAbsolutePath());
                }
            }
        }

        if (errors.isEmpty() && info.files.isEmpty()) {
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



}
