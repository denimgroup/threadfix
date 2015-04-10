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
package com.denimgroup.threadfix.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;

/**
 * Created by mcollins on 4/10/15.
 */
public class CustomPropertiesHolder {

    private static final SanitizedLogger LOG = new SanitizedLogger(CustomPropertiesHolder.class);

    // prevent instantiation
    private CustomPropertiesHolder() {}

    static {
        initializeConfiguredFields();
    }

    /**
     * This is for Defect Trackers
     * @param defectTrackerClass
     * @param name
     * @return
     */
    public static boolean showField(Class<?> defectTrackerClass, String name) {
        if (INCLUDE_ALL_SET.contains(defectTrackerClass)) {
            return true;
        } else if (!CONFIGURED_FIELDS.containsKey(defectTrackerClass)) {
            return true;
        } else {
            return CONFIGURED_FIELDS.get(defectTrackerClass).contains(name);
        }
    }

    private static Map<Class<?>, Set<String>> CONFIGURED_FIELDS = map();
    private static Set<Class<?>> INCLUDE_ALL_SET = set();

    private static Map<String, Class<? extends AbstractDefectTracker>> recognizedClassMap = map(
            "versionOne", VersionOneDefectTracker.class,
            "tfs", TFSDefectTracker.class,
            "jira", JiraDefectTracker.class,
            "hpqc", HPQualityCenterDefectTracker.class,
            "bugzilla", BugzillaDefectTracker.class
    );

    // TODO abstract this to another class
    private static void initializeConfiguredFields() {
        InputStream resourceAsStream =
                CustomPropertiesHolder.class
                        .getClassLoader()
                        .getResourceAsStream("custom.properties");

        if (resourceAsStream == null) {
            LOG.info("custom.properties not found, using default settings.");
        } else {
            Properties properties = new Properties();

            try {
                properties.load(resourceAsStream);
            } catch (IOException e) {
                LOG.error("Got IOException loading properties from defecttracker.properties");
            }

            for (Map.Entry<String, Class<? extends AbstractDefectTracker>> entry : recognizedClassMap.entrySet()) {
                if ("false".equals(properties.getProperty(entry.getKey() + ".includeAll"))) {
                    LOG.debug("Not including all fields for " + entry.getValue().getName() + ".");
                } else {
                    LOG.debug("Including all fields for " + entry.getValue().getName() + ".");
                    INCLUDE_ALL_SET.add(entry.getValue());
                }

                String includedFields = properties.getProperty("versionOne.includedFields");

                if (includedFields != null) {
                    CONFIGURED_FIELDS.put(entry.getValue(), set(includedFields.split(",")));
                }
            }
        }
    }

}
