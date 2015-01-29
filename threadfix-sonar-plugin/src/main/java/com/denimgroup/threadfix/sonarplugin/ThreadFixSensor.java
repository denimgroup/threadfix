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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.Sensor;
import org.sonar.api.batch.SensorContext;
import org.sonar.api.config.Settings;
import org.sonar.api.measures.Measure;
import org.sonar.api.resources.Project;

import java.util.Map;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixSensor implements Sensor {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixSensor.class);

    private final ThreadFixInfo info;

    public ThreadFixSensor(Settings settings) {
        Map<String, String> properties = settings.getProperties();

        LOG.info("Starting ThreadFix configuration check.");

        ThreadFixInfo info = new ThreadFixInfo(properties);

        if (!info.valid()) {
            LOG.info("Invalid ThreadFix configuration.");
            for (String error : info.getErrors()) {
                LOG.info(error);
            }
            this.info = null;
        } else if (testConnection(info)) {
            LOG.info("ThreadFix connection was valid.");
            this.info = info;
        } else {
            LOG.info("ThreadFix properties were present but the connection failed.");
            this.info = null;
        }
    }

    private boolean testConnection(ThreadFixInfo info) {
        // make call n stuff
        return false;
    }

    @Override
    public void analyse(Project project, SensorContext sensorContext) {

        if (info != null) {

            Measure measure = new Measure(ThreadFixMetrics.THREADFIX_STATISTICS, project.getName());
            sensorContext.saveMeasure(measure);

            // make calls to TF
        }
    }

    @Override
    public boolean shouldExecuteOnProject(Project project) {
        return true;
    }
}
