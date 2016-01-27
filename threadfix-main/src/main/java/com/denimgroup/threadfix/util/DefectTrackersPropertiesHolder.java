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
package com.denimgroup.threadfix.util;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.defects.*;

import java.util.Map;
import java.util.Set;

import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.util.RawPropertiesHolder.getProperty;

/**
 * Created by mcollins on 4/10/15.
 */
public class DefectTrackersPropertiesHolder {

    private static final SanitizedLogger LOG = new SanitizedLogger(DefectTrackersPropertiesHolder.class);

    // prevent instantiation
    private DefectTrackersPropertiesHolder() {}

    public static boolean showField(Class<?> defectTrackerClass, String name) {
        if (INCLUDE_ALL_SET.contains(defectTrackerClass)) {
            // include all means just return true
            return true;
        } else if (!CONFIGURED_FIELDS.containsKey(defectTrackerClass)) {
            // this means no fields were configured, so we should return false.
            return false;
        } else {
            // otherwise, return whether or not it's in the configured list
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

    static {
        initializeConfiguredFields();
    }

    private static void initializeConfiguredFields() {
        for (Map.Entry<String, Class<? extends AbstractDefectTracker>> entry : recognizedClassMap.entrySet()) {
            String name = entry.getValue().getName();

            if ("false".equals(getProperty(entry.getKey() + ".includeAll"))) {
                LOG.debug("Not including all fields for " + name + ".");
            } else {
                LOG.debug("Including all fields for " + name + ".");
                INCLUDE_ALL_SET.add(entry.getValue());
            }

            String includedFields = getProperty(entry.getKey() + ".includedFields");
            if (includedFields != null) {
                CONFIGURED_FIELDS.put(entry.getValue(), set(includedFields.split(",")));
            }
        }
    }

}
