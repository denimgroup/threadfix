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

import com.denimgroup.threadfix.annotations.ReportLocation;
import com.denimgroup.threadfix.annotations.ReportPlugin;
import com.denimgroup.threadfix.data.entities.DefaultConfiguration;
import com.denimgroup.threadfix.data.entities.Report;
import com.denimgroup.threadfix.importer.loader.AnnotationLoader;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.DefaultConfigService;
import com.denimgroup.threadfix.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * @author zabdisubhan
 */

@Component
public class ContextRefreshedListener implements ApplicationListener<ContextRefreshedEvent> {

    private final SanitizedLogger log = new SanitizedLogger(ContextRefreshedListener.class);

    @Autowired
    private ReportService reportService;

    @Autowired
    private DefaultConfigService defaultConfigService;

    private Report createAndSaveReport(Boolean nativeReport, String shortName, String displayName,
                                                     String jspFilePath, ReportLocation location) {
        return createAndSaveReport(nativeReport, shortName, displayName, jspFilePath, location, null);
    }

    private Report createAndSaveReport(Boolean nativeReport, String shortName, String displayName,
                                                     String jspFilePath, ReportLocation location, String jsFilePath) {
        Report report = new Report();

        report.setAvailable(true);
        report.setNativeReport(nativeReport);
        report.setShortName(shortName);
        report.setDisplayName(displayName);
        report.setJspFilePath(jspFilePath);
        report.setJspFilePath(jspFilePath);
        report.setLocation(location);

        if(jsFilePath != null && !jsFilePath.isEmpty()) {
            report.setJsFilePath(jsFilePath);
        }

        log.info("Storing new Report (" + report.getDisplayName() + " [" + report.getLocation() + "]).");
        reportService.store(report);

        return report;
    }

    private void addNativeReports() {

        DefaultConfiguration config = defaultConfigService.loadCurrentConfiguration();

        Map<ReportLocation, Report> vulnTrendReports = map();
        Map<ReportLocation, Report> mostVulnAppsReports = map();

        for (ReportLocation location : ReportLocation.values()) {
            vulnTrendReports.put(location,
                 createAndSaveReport(
                     true,
                     "vulnerabilityTrending",
                     "Vulnerability Trending",
                     "/WEB-INF/views/applications/widgets/vulnerabilityTrending.jsp",
                     location,
                     "/scripts/left-report-controller.js"));

            mostVulnAppsReports.put(location,
                    createAndSaveReport(
                        true,
                        "mostVulnerableApps",
                        "Most Vulnerable Applications",
                        "/WEB-INF/views/applications/widgets/mostVulnerableApps.jsp",
                        location,
                        "/scripts/right-report-controller.js"));
        }

        config.setDashboardTopLeft(vulnTrendReports.get(ReportLocation.DASHBOARD));

        config.setDashboardTopRight(mostVulnAppsReports.get(ReportLocation.DASHBOARD));

        config.setApplicationTopLeft(vulnTrendReports.get(ReportLocation.APPLICATION));

        config.setApplicationTopRight(mostVulnAppsReports.get(ReportLocation.APPLICATION));

        config.setTeamTopLeft(vulnTrendReports.get(ReportLocation.TEAM));

        config.setTeamTopRight(mostVulnAppsReports.get(ReportLocation.TEAM));

        config.setDashboardBottomLeft(createAndSaveReport(
                true,
                "recentUploads",
                "Recent Uploads",
                "/WEB-INF/views/applications/widgets/recentUploads.jsp",
                ReportLocation.DASHBOARD));

        config.setDashboardBottomRight(createAndSaveReport(
                true,
                "recentComments",
                "Recent Comments",
                "/WEB-INF/views/applications/widgets/recentComments.jsp",
                ReportLocation.DASHBOARD));

        defaultConfigService.saveConfiguration(config);
        log.info("Setting native Dashboard, Application and Team Detail Page Reports positions in Default Configuration.");
    }

    @SuppressWarnings("unchecked")
    public void onApplicationEvent(ContextRefreshedEvent event) {

        if(!reportService.isInitialized()) {

            reportService.setInitialized(true);

            if (reportService.loadAllNativeReports().size() == 0) {
                addNativeReports();
            }

            List<Report> reports = reportService.loadAllNonNativeReports();
            Map<Report, Boolean> availableReportPlugins = map();

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
                        || annotation.shortName().isEmpty() || annotation.locations().length == 0) {

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
                            log.info("Plugin for existing Report (" + report.getDisplayName() +
                                    " [" + report.getLocation() + "]) was found. Setting availability to true.");
                            report.setAvailable(true);
                            reportService.store(report);
                        }
                    }
                }

                if (r != null && availableReportPlugins.get(r)) {
                    log.info("ReportPlugin already exists as a Report. Skip to next ReportPlugin.");
                    continue;
                }

                // create as many report obj as the plugin has locations for
                for (ReportLocation location : annotation.locations()){
                    createAndSaveReport(false, annotation.shortName(), annotation.displayName(),
                            annotation.jspRelFilePath(), location, annotation.jsRelFilePath());
                }
            }

            // set the availability of dashboard & application detail page reports
            // that were not found as plugins to false
            for (Report report : availableReportPlugins.keySet()) {
                if (!availableReportPlugins.get(report)) {
                    if (report.getAvailable()) {
                        log.info("Plugin for existing Report (" + report.getDisplayName() +
                                " [" + report.getLocation() + "]) not found. Setting availability to false.");
                        report.setAvailable(false);
                        reportService.store(report);
                    }
                }
            }
        }
    }
}
