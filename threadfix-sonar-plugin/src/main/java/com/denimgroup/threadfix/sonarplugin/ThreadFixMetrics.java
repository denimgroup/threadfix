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
import org.sonar.api.measures.CoreMetrics;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metrics;

import java.util.Arrays;
import java.util.List;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixMetrics implements Metrics {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixMetrics.class);

    public static final Metric THREADFIX_STATISTICS=
            new Metric.Builder(
                    "threadfix_total_vulns", // metric identifier
                    "Total ThreadFix Vulnerabilities", // metric name
                    Metric.ValueType.INT) // metric data type
                    .setDescription("Number of ThreadFix vulnerabilities for this application.")
                    .setDomain(CoreMetrics.DOMAIN_GENERAL)
                    .create();


    @Override
    public List<Metric> getMetrics() {
        return Arrays.asList(THREADFIX_STATISTICS);
    }
}
