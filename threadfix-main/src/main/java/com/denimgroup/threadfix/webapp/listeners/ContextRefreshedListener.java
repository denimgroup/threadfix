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

package com.denimgroup.threadfix.webapp.listeners;

import com.denimgroup.threadfix.annotations.ReportPlugin;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.importer.loader.AnnotationLoader;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.newMap;

/**
 * @author zabdisubhan
 */

@Component
public class ContextRefreshedListener implements ApplicationListener<ContextRefreshedEvent> {

    private final SanitizedLogger log = new SanitizedLogger(ContextRefreshedListener.class);

    @Autowired
    private ReportService reportService;

    @SuppressWarnings("unchecked")
    public void onApplicationEvent(ContextRefreshedEvent event) {

        if(!reportService.isInitialized()) {

            reportService.setInitialized(true);

            List<Report> reports = reportService.loadAllNonNativeReports();
            Map<Report, Boolean> availableReportPlugins = newMap();

            for (Report report : reports) {
                if (report.getAvailable()) {
                    availableReportPlugins.put(report, false);
                }
            }

            Map<Class<?>, ReportPlugin> typeMap =
                    AnnotationLoader.getMap(
                            ReportPlugin.class,
                            "com.denimgroup.threadfix");

            log.info("ReportPlugin map has " + typeMap.entrySet().size() + " entries.");

            for (Map.Entry<Class<?>, ReportPlugin> entry : typeMap.entrySet()) {
                ReportPlugin annotation = entry.getValue();

                if (annotation.displayName().isEmpty() || annotation.jspRelFilePath().isEmpty()
                        || annotation.shortName().isEmpty()) {

                    log.warn("Required attrs for ReportPlugin were empty. Skip to next ReportPlugin.");
                    continue;
                }

                Report r = null;

                for (Report report : reports) {
                    if (report.getShortName().equals(annotation.shortName())) {

                        // note that report plugin is available to Threadfix
                        r = report;
                        availableReportPlugins.put(report, true);

                        // set previously unavailable report plugin to true
                        // now that plugin has be re-added to Threadfix
                        if (!report.getAvailable()) {
                            log.info("Plugin for existing Report [" + report.getDisplayName() +
                                    "] was found. Setting availability to true.");
                            report.setAvailable(true);
                            reportService.store(report);
                        }
                    }
                }

                if (r != null && availableReportPlugins.get(r)) {
                    log.info("ReportPlugin already exists as a Report. Skip to next ReportPlugin.");
                    continue;
                }

                Report report = new Report();

                report.setAvailable(true);
                report.setNativeReport(false);
                report.setShortName(annotation.shortName());
                report.setDisplayName(annotation.displayName());
                report.setJspFilePath(annotation.jspRelFilePath());
                report.setJsFilePath(annotation.jsRelFilePath());

                log.info("Storing new Report [" + annotation.displayName() + "].");
                reportService.store(report);
            }

            // set dashboard reports' availability that were not found in annotations to false
            for (Report report : availableReportPlugins.keySet()) {
                if (!availableReportPlugins.get(report)) {
                    if (report.getAvailable()) {
                        log.info("Plugin for existing Report [" + report.getDisplayName() +
                                "] not found. Setting availability to false.");
                        report.setAvailable(false);
                        reportService.store(report);
                    }
                }
            }
        }
    }
}
