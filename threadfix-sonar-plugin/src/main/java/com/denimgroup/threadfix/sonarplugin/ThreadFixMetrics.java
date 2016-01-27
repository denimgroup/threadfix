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
package com.denimgroup.threadfix.sonarplugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.measures.Metric;
import org.sonar.api.measures.Metric.Builder;
import org.sonar.api.measures.Metric.ValueType;
import org.sonar.api.measures.Metrics;

import java.util.Arrays;
import java.util.List;

/**
 * Created by mcollins on 1/28/15.
 */
public class ThreadFixMetrics implements Metrics {

    private static final Logger LOG = LoggerFactory.getLogger(ThreadFixMetrics.class);

    public static Metric
            TOTAL_VULNS = (new Builder("threadfix-total-vulns", "ThreadFix Total Vulnerabilities", ValueType.INT)).setDescription("ThreadFix Total Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create(),
            CRITICAL_VULNS = (new Builder("threadfix-critical-vulns", "ThreadFix Critical Vulnerabilities", ValueType.INT)).setDescription("ThreadFix Critical Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create(),
            HIGH_VULNS = (new Builder("threadfix-high-vulns", "ThreadFix High Vulnerabilities", ValueType.INT)).setDescription("ThreadFix High Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create(),
            MEDIUM_VULNS = (new Builder("threadfix-medium-vulns", "ThreadFix Medium Vulnerabilities", ValueType.INT)).setDescription("ThreadFix Medium Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create(),
            LOW_VULNS = (new Builder("threadfix-low-vulns", "ThreadFix Low Vulnerabilities", ValueType.INT)).setDescription("ThreadFix Low Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create(),
            INFO_VULNS = (new Builder("threadfix-info-vulns", "ThreadFix Informational Vulnerabilities", ValueType.INT)).setDescription("ThreadFix Informational Vulnerabilities").setDirection(1).setQualitative(true).setDomain("ThreadFix").setBestValue(0.0D).create();

    @Override
    public List<Metric> getMetrics() {
        return Arrays.asList(TOTAL_VULNS, CRITICAL_VULNS, HIGH_VULNS, MEDIUM_VULNS, LOW_VULNS, INFO_VULNS);
    }
}
