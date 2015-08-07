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
package com.denimgroup.threadfix.selenium.weekend;

import com.denimgroup.threadfix.WeekendTests;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.TimeoutException;

import static org.junit.Assert.assertTrue;

@Category(WeekendTests.class)
public class SlowFilterIT extends BaseIT{

    @Test
    public void globalFiltersTest() {
        try {
            String teamName1 = getRandomString(8);
            String teamName2 = getRandomString(8);
            String appName1 = getRandomString(8);
            String appName2 = getRandomString(8);
            String file = ScanContents.getScanFilePath();

            String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
            String severity = "High";

            DatabaseUtils.createTeam(teamName1);
            DatabaseUtils.createApplication(teamName1, appName1);
            DatabaseUtils.uploadScan(teamName1, appName1, file);
            DatabaseUtils.createTeam(teamName2);
            DatabaseUtils.createApplication(teamName2, appName2);
            DatabaseUtils.uploadScan(teamName2, appName2, file);

            CustomizeVulnerabilityTypesPage customizeVulnerabilityTypesPage = loginPage.defaultLogin()
                    .clickCustomizeThreadFixVulnerabilityTypesLink()
                    .clickCreateNewFilter()
                    .addVulnerabilityFilter(vulnerabilityType, severity)
                    .closeSuccessNotification();

            CustomizeSeveritiesPage customizeSeveritiesPage = customizeVulnerabilityTypesPage.clickCustomizeThreadFixSeveritiesLink()
                    .clickShowHideTab()
                    .enableSeverityFilters()
                    .hideMedium()
                    .saveFilterChanges()
                    .waitForChanges();

            TeamIndexPage teamIndexPage = customizeSeveritiesPage.clickOrganizationHeaderLink();
            sleep(3000);

            assertTrue("The global filter for " + teamName1 + " was not implemented correctly - medium should be 0.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Medium", "0"));
            assertTrue("The global filter for team1 was not implemented correctly - Info should be  10.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Info", "10"));
            assertTrue("The global severity filter for team1 was not set properly - High should be 2.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "High", "2"));

            assertTrue("The global filter for team2 was not implemented correctly - medium should be 0.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "Medium", "0"));
            assertTrue("The global filter for team2 was not implemented correctly - Info should be 10.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "Info", "10"));
            assertTrue("The global severity filter for team2 was not set properly - High should be 2.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "High", "2"));

            loginPage = teamIndexPage.logout();
            clearGlobalFilter();
        } catch (TimeoutException t ) {
            System.err.println(t.getMessage());
            loginPage.logout();
            clearGlobalFilter();
            throw new RuntimeException("Test failed cleaning up filter.", t);
        } catch (NoSuchElementException e) {
            loginPage.logout();
            System.err.println(e.getMessage());
            clearGlobalFilter();
            throw e;
        } catch (AssertionError a){
            loginPage.logout();
            clearGlobalFilter();
            throw a;
        }
    }

    @Test
    public void layeredFilterTest() {
        try {
            String teamName = getRandomString(8);
            String appName = getRandomString(8);
            String file = ScanContents.getScanFilePath();

            String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
            String severity = "High";

            DatabaseUtils.createTeam(teamName);
            DatabaseUtils.createApplication(teamName, appName);
            DatabaseUtils.uploadScan(teamName, appName, file);

            // Set global severity filter for vulnerabilityType1 and hide 'Medium', 'Low', 'Info' vulnerabilities
            CustomizeVulnerabilityTypesPage customizeVulnerabilityTypesPage = loginPage.defaultLogin()
                    .clickCustomizeThreadFixVulnerabilityTypesLink()
                    .clickCreateNewFilter()
                    .addVulnerabilityFilter(vulnerabilityType, severity)
                    .closeSuccessNotification();

            CustomizeSeveritiesPage customizeSeveritiesPage = customizeVulnerabilityTypesPage.clickCustomizeThreadFixSeveritiesLink()
                    .clickShowHideTab()
                    .enableSeverityFilters()
                    .hideMedium()
                    .hideLow()
                    .hideInfo()
                    .saveFilterChanges()
                    .waitForChanges();

            TeamIndexPage teamIndexPage = customizeSeveritiesPage.clickOrganizationHeaderLink();

            // Set teamName to show 'Medium' vulnerabilities
            TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName);

            TeamAppCustomizeVulnerabilityTypesPage teamCustomizeVulnerabilityTypesPage = teamDetailPage.clickActionButton()
                    .clickEditTeamFilters()
                    .enableSeverityFilters()
                    .showMedium()
                    .saveFilterChanges();

            teamIndexPage = teamCustomizeVulnerabilityTypesPage.clickOrganizationHeaderLink();

            // Set appName1 to hide 'Critical'
            ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                    .clickViewAppLink(appName, teamName);

            TeamAppCustomizeVulnerabilityTypesPage appCustomizeVulnerabilityTypesPage = applicationDetailPage.clickActionButton()
                    .clickEditVulnerabilityFilters()
                    .enableSeverityFilters()
                    .hideCritical()
                    .saveFilterChanges();

            // Check TeamIndexPage to for the final results
            teamIndexPage = appCustomizeVulnerabilityTypesPage.clickOrganizationHeaderLink();

            assertTrue("Application filter of hiding 'Critical' was not implemented correctly.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Critical", "0"));
            assertTrue("Global and Team severity filter changes were not implemented correctly.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName, "High", "2"));
            assertTrue("Team filter of showing 'Medium' was not implemented correctly.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium", "6"));
            assertTrue("Global filter of hiding 'Low' was not implemented correctly.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Low", "0"));
            assertTrue("Application filter of showing 'Info' was not implemented correctly.",
                    teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info", "0"));

            loginPage = teamIndexPage.logout();
            clearGlobalFilter();
        } catch (TimeoutException t ) {
            System.err.println(t.getMessage());
            loginPage.logout();
            clearGlobalFilter();
            throw new RuntimeException("Test failed cleaning up filter.", t);
        } catch (NoSuchElementException e) {
            loginPage.logout();
            System.err.println(e.getMessage());
            clearGlobalFilter();
            throw e;
        } catch (AssertionError a) {
            loginPage.logout();
            clearGlobalFilter();
            throw a;
        }
    }

    public void clearGlobalFilter() {
        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        try {
            CustomizeVulnerabilityTypesPage customizeVulnerabilityTypesPage = teamIndexPage.clickCustomizeThreadFixVulnerabilityTypesLink()
                    .deleteFilter()
                    .closeSuccessNotification();
            teamIndexPage = customizeVulnerabilityTypesPage.clickOrganizationHeaderLink();
        } catch (NoSuchElementException e) {
            System.out.println("There was not a global vulnerability filter set.");
        }

        CustomizeSeveritiesPage customizeSeveritiesPage = teamIndexPage.clickCustomizeThreadFixSeveritiesLink()
                .clickShowHideTab()
                .enableSeverityFilters()
                .showCritical()
                .showHigh()
                .showMedium()
                .showLow()
                .showInfo()
                .disableSeverityFilters()
                .saveFilterChanges()
                .waitForChanges();

        loginPage = customizeSeveritiesPage.logout();
    }
}
