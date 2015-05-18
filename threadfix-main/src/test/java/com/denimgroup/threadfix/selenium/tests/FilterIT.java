////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.FilterPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class FilterIT extends BaseIT {
    // TODO if a notification system is implemented then get rid of sleeps...just refresh the page when the work is done

    @Test
    public void testApplicationFilters() {
        String teamName = createTeam();
        String appName1 = createApplication(teamName);
        String appName2 = createApplication(teamName);
        String file = ScanContents.getScanFilePath();

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
        String severity = "High";

        DatabaseUtils.uploadScan(teamName, appName1, file);
        DatabaseUtils.uploadScan(teamName, appName2, file);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        FilterPage applicationFilterPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName1, teamName)
                .clickActionButton()
                .clickEditVulnerabilityFilters()
                .clickCreateNewFilter()
                .addVulnerabilityFilter(vulnerabilityType, severity)
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = applicationFilterPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "High", "2"));
        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Medium", "0"));
        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Info", "0"));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName1, teamName);

        assertTrue("Vulnerabilities were not filtered properly on application detail page.",
                applicationDetailPage.vulnsFilteredOpen(10));
    }

    @Test
    public void testTeamFilters() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String file = ScanContents.getScanFilePath();

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
        String severity = "High";

        DatabaseUtils.uploadScan(teamName, appName, file);

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        FilterPage teamFilterPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickActionButton()
                .clickEditTeamFilters()
                .clickCreateNewFilter()
                .addVulnerabilityFilter(vulnerabilityType, severity)
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = teamFilterPage.clickOrganizationHeaderLink();

        assertTrue("The filter was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium", "0"));
        assertTrue("The filter was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info", "0"));
        assertTrue("The severity filter was not set properly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, severity, "2"));

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName);

        assertTrue("The filter was not implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "Medium", "0"));
        assertTrue("The filter was not implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "Info", "0"));
        assertTrue("The severity filter was implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "High", "2"));
    }

    @Test
    public void testEditFilters() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String file = ScanContents.getScanFilePath();

        DatabaseUtils.uploadScan(teamName, appName, file);

        // Set teamName to show 'Medium' vulnerabilities
        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName);

        FilterPage teamFilterPage = teamDetailPage.clickActionButton()
                .clickEditTeamFilters()
                .enableSeverityFilters()
                .hideMedium()
                .saveFilterChanges();

        TeamIndexPage teamIndexPage = teamFilterPage.clickOrganizationHeaderLink();

        // Set appName1 to hide 'Critical'
        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        FilterPage applicationFilterPage = applicationDetailPage.clickActionButton()
                .clickEditVulnerabilityFilters()
                .enableSeverityFilters()
                .hideCritical()
                .saveFilterChanges();

        // Check TeamIndexPage to for the results
        teamIndexPage = applicationFilterPage.clickOrganizationHeaderLink();

        assertTrue("Critical vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Critical", "0"));
        assertTrue("High vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "High", "0"));
        assertTrue("Medium vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium", "0"));
        assertTrue("Low vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Low", "4"));
        assertTrue("Info vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info", "9"));

        applicationFilterPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickActionButton()
                .clickEditVulnerabilityFilters()
                .showCritical()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = applicationFilterPage.clickOrganizationHeaderLink();

        assertTrue("Critical vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Critical", "6"));
        assertTrue("High vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "High", "0"));
        assertTrue("Medium vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium", "0"));
        assertTrue("Low vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Low", "4"));
        assertTrue("Info vulnerability count was not correct.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info", "0"));
    }
}

