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

package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.engine.framework.ClassMapping;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;

public class SpringServletConfigurationChecker {

    public static final String DISPATCHER_SERVLET = "org.springframework.web.servlet.DispatcherServlet",
        CONFIG_CLASS = "org.springframework.web.context.support.AnnotationConfigWebApplicationContext";

    private static final SanitizedLogger log = new SanitizedLogger("SpringServletConfigurationChecker");

    private static final String CONTEXT_CLASS = "contextClass",
        CONTEXT_CONFIG_LOCATION = "contextConfigLocation",
        CLASSPATH = "classpath:";

    ProjectDirectory projectDirectory;
    @Nonnull ClassMapping mapping;
    @Nonnull Map<String, String> contextParams;

    private SpringServletConfigurationChecker(ProjectDirectory projectDirectory,
                                              @Nonnull ClassMapping mapping,
                                              @Nonnull Map<String, String> contextParams) {
        this.projectDirectory = projectDirectory;
        this.mapping = mapping;
        this.contextParams = contextParams;
    }

    public static boolean checkServletConfig(ProjectDirectory projectDirectory,
                                             @Nonnull ClassMapping mapping,
                                             @Nonnull Map<String, String> contextParams) {
        boolean result = false;

        if (mapping.getClassWithPackage().equals(DISPATCHER_SERVLET)) {

            if (mapping.getContextClass() != null && mapping.getContextClass().equals(CONFIG_CLASS)) {
                result = true;
            } else if (contextParams.containsKey(CONTEXT_CLASS) && contextParams.get(CONTEXT_CLASS).equals(CONFIG_CLASS)) {
                result = true;
            } else {
                result = new SpringServletConfigurationChecker(projectDirectory, mapping, contextParams).lookInXmlFiles();
            }
        }

        return result;
    }

    private boolean lookInXmlFiles() {
        // Spring. Let's look for mvc:annotation-driven in the servlet config

        boolean result = false;

        List<File> configFiles = list();

        configFiles.addAll(getFilesFromConfigString(mapping.getContextConfigLocation()));
        configFiles.addAll(getFilesFromConfigString(contextParams.get(CONTEXT_CONFIG_LOCATION)));
        configFiles.add(projectDirectory.findFile(mapping.getServletName() + "-servlet.xml"));

        for (File configFile : configFiles) {
            log.info("Checking config file " + configFile);
            if (configFile != null && DispatcherServletParser.usesSpringMvcAnnotations(configFile)) {
                log.info("Dispatcher servlet configuration parsing found Spring MVC configuration.");
                result = true;
                break;
            } else if (configFile == null) {
                log.info("Unable to locate configuration file.");
            }
        }

        return result;
    }

    private Collection<File> getFilesFromConfigString(String contextConfigLocation) {

        List<File> files = list();

        if (contextConfigLocation != null) {

            contextConfigLocation = contextConfigLocation.trim();

            if (contextConfigLocation.trim().contains("\n")) {
                String[] strings = contextConfigLocation.split("\n");

                for (String string : strings) {
                    files.addAll(cleanAndGetFiles(string));
                }
            } else {
                files.addAll(cleanAndGetFiles(contextConfigLocation));
            }
        }

        return files;
    }

    private Collection<File> cleanAndGetFiles(String line) {
        String cleaned = line;

        List<File> returnStrings = list();

        if (cleaned.trim().startsWith(CLASSPATH)) {
            cleaned = cleaned.trim().substring(CLASSPATH.length());
        }

        if (cleaned.contains(",")) {
            String[] strings = cleaned.split(","); // I guess they can also be comma separated

            for (String string : strings) {
                returnStrings.addAll(projectDirectory.findFiles(string.trim()));
            }
        } else {
            returnStrings = projectDirectory.findFiles(cleaned.trim());
        }

        return returnStrings;
    }
}
