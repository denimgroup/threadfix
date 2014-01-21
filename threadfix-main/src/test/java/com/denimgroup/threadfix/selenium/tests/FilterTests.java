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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.denimgroup.threadfix.selenium.pages.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.Organization;


public class FilterTests extends BaseTest{

    public FilterTests(String browser){
        super(browser);
    }

    private RemoteWebDriver driver;
    private static LoginPage loginPage;

    private TeamIndexPage teamIndexPage;
    private TeamDetailPage teamDetailPage;
    private ApplicationDetailPage applicationDetailPage;
    private FilterPage teamFilterPage;
    private FilterPage applicationFilterPage;
    private FilterPage globalFilterPage;

    private String fileBase = System.getProperty("scanFileBaseLocation");
    private String fileSeparator = System.getProperty("file.separator");

    @Before
    public void init() {
        super.init();
        driver = (RemoteWebDriver)super.getDriver();
        loginPage = LoginPage.open(driver);
    }

    @After
    public void shutDown() {
        clearGlobalFilter();
        driver.quit();
    }

    // TODO test if you can edit an existing filter and ensure the results are correct
    @Ignore
    @Test
    public void testEditVulnerabilityFilterTest() {

    }

    @Test
    public void testApplicationFilters() {
        String teamName = getRandomString(8);
        String appName1 = getRandomString(8);
        String appName2 = getRandomString(8);
        String file = fileBase + "SupportingFiles" + fileSeparator + "Dynamic" + fileSeparator + "Acunetix"
                + fileSeparator + "testaspnet.xml";

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
        String severity = "High";

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .addNewApplication(teamName, appName1, "", "Low")
                .saveApplication(teamName)
                .clickUploadScan(appName1, teamName)
                .setFileInput(file)
                .clickUploadScanButton(teamName, appName1);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.addNewApplication(teamName, appName2, "", "Low")
                .saveApplication(teamName)
                .clickUploadScan(appName2, teamName)
                .setFileInput(file)
                .clickUploadScanButton(teamName, appName2);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        applicationFilterPage = teamIndexPage.expandTeamRowByIndex(teamName)
                .clickViewAppLink(appName1, teamName)
                .clickActionButton()
                .clickEditVulnerabilityFilters()
                .clickCreateNewFilter()
                .setVulnerabilityType(vulnerabilityType)
                .setSeverity(severity)
                .addFilter()
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = applicationFilterPage.clickOrganizationHeaderLink()
                .expandTeamRowByIndex(teamName);

        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "High", "2"));
        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Medium", "0"));
        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Info", "0"));


        applicationDetailPage = teamIndexPage.clickViewAppLink(appName1, teamName);

        assertTrue("Vulnerabilities were not filtered properly on application detail page.",
                applicationDetailPage.vulnerabilitiesFiltered("High", "2"));
        assertTrue("Vulnerabilities were not filtered properly on application detail page.",
                applicationDetailPage.vulnerabilitiesFiltered("Medium", "0"));
        assertTrue("Vulnerabilities were not filtered properly on application detail page.",
                applicationDetailPage.vulnerabilitiesFiltered("Info", "0"));

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    @Test
    public void testTeamFilters() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String file = fileBase + "SupportingFiles" + fileSeparator + "Dynamic" + fileSeparator + "Acunetix"
                + fileSeparator + "testaspnet.xml";

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
        String severity = "High";

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication(teamName)
                .clickUploadScan(appName, teamName)
                .setFileInput(file)
                .clickUploadScanButton(teamName, appName);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        teamFilterPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickActionButton()
                .clickEditTeamFilters()
                .clickCreateNewFilter()
                .setVulnerabilityType(vulnerabilityType)
                .setSeverity(severity)
                .addFilter()
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = teamFilterPage.clickOrganizationHeaderLink();

        assertTrue("The filter was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium", "0"));
        assertTrue("The filter was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info","0"));
        assertTrue("The severity filter was not set properly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName, severity, "2"));

        teamDetailPage = teamIndexPage.clickViewTeamLink(teamName);

        assertTrue("The filter was not implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "Medium", "0"));
        assertTrue("The filter was not implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "Info", "0"));
        assertTrue("The severity filter was implemented correctly",
                teamDetailPage.applicationVulnerabilitiesFiltered(appName, "High", "2"));

        teamIndexPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    @Test
    public void testGlobalFilters() {
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);
        String appName1 = getRandomString(8);
        String appName2 = getRandomString(8);
        String file = fileBase + "SupportingFiles" + fileSeparator + "Dynamic" + fileSeparator + "Acunetix"
                + fileSeparator + "testaspnet.xml";

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName1)
                .addNewTeam()
                .clickAddTeamButton()
                .setTeamName(teamName2)
                .addNewTeam()
                .addNewApplication(teamName1, appName1, "", "Low")
                .saveApplication(teamName1)
                .clickUploadScan(appName1, teamName1)
                .setFileInput(file)
                .clickUploadScanButton(teamName1, appName1);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        applicationDetailPage = teamIndexPage.addNewApplication(teamName2, appName2, "", "Low")
                .saveApplication(teamName2)
                .clickUploadScan(appName2, teamName2)
                .setFileInput(file)
                .clickUploadScanButton(teamName2, appName2);

        globalFilterPage = applicationDetailPage.clickOrganizationHeaderLink().clickManageFiltersLink();

        globalFilterPage = globalFilterPage
                .clickCreateNewFilter()
                .setVulnerabilityType(vulnerabilityType)
                .setSeverity("High")
                .addFilter()
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = globalFilterPage.clickOrganizationHeaderLink();

        assertTrue("The global filter for team1 was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Medium", "0"));
        assertTrue("The global filter for team1 was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Info","0"));
        assertTrue("The global severity filter for team1 was not set properly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "High", "2"));

        assertTrue("The global filter for team2 was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "Medium", "0"));
        assertTrue("The global filter for team2 was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "Info","0"));
        assertTrue("The global severity filter for team2 was not set properly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName2, "High", "2"));

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName1)
                .clickDeleteButton()
                .clickViewTeamLink(teamName2)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    @Test
    public void layeredFilterTest() {
        String teamName1 = getRandomString(8);
        String appName1 = getRandomString(8);
        String file = fileBase + "SupportingFiles" + fileSeparator + "Dynamic" + fileSeparator + "Acunetix"
                + fileSeparator + "testaspnet.xml";

        String vulnerabilityType1 = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";
        String severity = "High";

        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        // Team and App set up, add scans
        applicationDetailPage = teamIndexPage.clickAddTeamButton()
                .setTeamName(teamName1)
                .addNewTeam()
                .addNewApplication(teamName1, appName1, "", "Low")
                .saveApplication(teamName1)
                .clickUploadScan(appName1, teamName1)
                .setFileInput(file)
                .clickUploadScanButton(teamName1, appName1);

        teamIndexPage = applicationDetailPage.clickOrganizationHeaderLink();

        // Set global severity filter for vulnerabilityType1 and hide 'Medium', 'Low', 'Info' vulnerabilities
        globalFilterPage = teamIndexPage.clickManageFiltersLink()
                .clickCreateNewFilter()
                .setVulnerabilityType(vulnerabilityType1)
                .setSeverity("High")
                .addFilter()
                .closeSuccessNotification()
                .enableSeverityFilters()
                .hideMedium()
                .hideLow()
                .hideInfo()
                .saveFilterChanges();

        teamIndexPage = globalFilterPage.clickOrganizationHeaderLink();
        
        // Set teamName1 to show 'Medium' vulnerabilities
        teamDetailPage = teamIndexPage.clickViewTeamLink(teamName1);
        
        teamFilterPage = teamDetailPage.clickActionButton()
                .clickEditTeamFilters()
                .enableSeverityFilters()
                .showMedium()
                .saveFilterChanges();

        teamIndexPage = teamFilterPage.clickOrganizationHeaderLink();

        // Set appName1 to  to hide 'Critical'
        applicationDetailPage = teamIndexPage.expandTeamRowByIndex(teamName1)
                .clickViewAppLink(appName1, teamName1);

        applicationFilterPage = applicationDetailPage.clickActionButton()
                .clickEditVulnerabilityFilters()
                .enableSeverityFilters()
                .hideCritical()
                .saveFilterChanges();

        // Check TeamIndexPage to for the final results
        teamIndexPage = applicationFilterPage.clickOrganizationHeaderLink();

        assertTrue("Application filter of hiding 'Critical' was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Critical", "0"));
        assertTrue("Global and Team severity filter changes were not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "High", "2"));
        assertTrue("Team filter of showing 'Medium' was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Medium", "6"));
        assertTrue("Global filter of hiding 'Low' was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Low", "4"));
        assertTrue("Application filter of showing 'Info' was not implemented correctly.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName1, "Info", "10"));


        teamIndexPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName1)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }

    public void clearGlobalFilter() {
        teamIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink();

        try {
            globalFilterPage = teamIndexPage.clickManageFiltersLink()
                    .deleteFilter()
                    .closeSuccessNotification();

            teamIndexPage = globalFilterPage.clickOrganizationHeaderLink();
        } catch (NoSuchElementException e) {
            System.out.println("There was not a global vulnerability filter set.");
        }
        globalFilterPage = teamIndexPage.clickManageFiltersLink()
                .enableSeverityFilters()
                .showCritical()
                .showHigh()
                .showMedium()
                .showLow()
                .showInfo()
                .disableSeverityFilters()
                .saveFilterChanges();

        loginPage = teamIndexPage.logout();

    }
}

