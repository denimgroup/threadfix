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
        driver.quit();
    }

    // TODO in progress
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
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Medium"));
        assertTrue("Vulnerabilities were not filtered properly on team index page.",
                teamIndexPage.applicationVulnerabilitiesFiltered(teamName, appName1, "Info"));


        applicationDetailPage = teamIndexPage.clickViewAppLink(appName1, teamName);

        assertTrue("Vulnerabilities were not filtered properly on application detail page.",
                applicationDetailPage.vulnerabilitiesFiltered("High", "2"));

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

        assertTrue("The filter was not implemented correctly.", teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Medium"));
        assertTrue("The filter was not implemented correctly.", teamIndexPage.teamVulnerabilitiesFiltered(teamName, "Info"));

        assertTrue("The severity filter was not set properly.", teamIndexPage.severityChanged(teamName, severity, "2"));

        teamIndexPage = teamIndexPage.clickViewTeamLink(teamName)
                .clickDeleteButton();

        loginPage = teamIndexPage.logout();
    }
}
