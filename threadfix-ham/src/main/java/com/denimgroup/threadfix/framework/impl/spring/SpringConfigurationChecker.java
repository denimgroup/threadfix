package com.denimgroup.threadfix.framework.impl.spring;

import com.denimgroup.threadfix.framework.engine.ClassMapping;
import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by mac on 1/6/14.
 */
public class SpringConfigurationChecker {

    public static final String DISPATCHER_SERVLET = "org.springframework.web.servlet.DispatcherServlet",
        CONFIG_CLASS = "org.springframework.web.context.support.AnnotationConfigWebApplicationContext";

    private static final SanitizedLogger log = new SanitizedLogger("SpringConfigurationChecker");

    public static boolean check(ProjectDirectory projectDirectory, @NotNull ClassMapping mapping) {
        boolean result = false;

        if (mapping.getClassWithPackage().equals(DISPATCHER_SERVLET)) {

            if (mapping.getContextClass() != null && mapping.getContextClass().equals(CONFIG_CLASS)) {
                result = true;
            } else {
                result = lookInXmlFiles(projectDirectory, mapping);
            }
        }

        return result;
    }

    private static boolean lookInXmlFiles(ProjectDirectory projectDirectory, @NotNull ClassMapping mapping) {
        // Spring. Let's look for mvc:annotation-driven in the servlet config

        boolean result = false;

        List<File> configFiles = new ArrayList<>();

        if (mapping.getContextConfigLocation() != null &&
                mapping.getContextConfigLocation().trim().contains("\n")) {
            // There may be multiple configuration files. We have to run through all of them
            // and look for spring mvc stuff because we don't know which will have the config beforehand.
            String[] strings = mapping.getContextConfigLocation().split("\n");

            for (String string : strings) {
                List<File> files = projectDirectory.findFiles(string.trim());
                configFiles.addAll(files);
            }
        } else if (mapping.getContextConfigLocation() != null) {
            configFiles.addAll(projectDirectory.findFiles(mapping.getContextConfigLocation().trim()));
        }

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
}
