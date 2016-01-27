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
package com.denimgroup.threadfix.sonarplugin.util;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.sonarplugin.configuration.ThreadFixInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.rule.Severity;

import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * Created by mcollins on 2/4/15.
 */
public class ThreadFixTools {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixTools.class);

    private ThreadFixTools() {}

    public static String getApplicationId(ThreadFixInfo info) {
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


    // fancy
    private static Map<String, String> severityMap = map(
            GenericSeverity.CRITICAL, Severity.BLOCKER,
            GenericSeverity.HIGH, Severity.CRITICAL,
            GenericSeverity.MEDIUM, Severity.MAJOR,
            GenericSeverity.LOW, Severity.MINOR,
            GenericSeverity.INFO, Severity.INFO);

    public static String getSonarSeverity(VulnerabilityMarker vulnerability) {
        String severity = vulnerability.getSeverity();
        return severityMap.containsKey(severity) ? severityMap.get(severity) : Severity.MAJOR;
    }

}
