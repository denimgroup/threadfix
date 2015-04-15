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
package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.AnalyticsPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TagDetailPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class AnalyticsEntIT extends BaseDataTest {

    @Test
    public void testUtilsAttachPciTag() {
        initializeTeamAndAppWithIbmScan();
        DatabaseUtils.attachAppToTag("PCI",appName,teamName);

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickComplianceTab(true)
                .selectComplianceType("PCI");
    }

    @Test
    public void testUtilsAttachHipaaTag() {
        initializeTeamAndAppWithIbmScan();
        DatabaseUtils.attachAppToTag("HIPAA",appName,teamName);

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickComplianceTab(true)
                .selectComplianceType("HIPAA");
    }

    @Test
    public void testManuallyAttachPciTagToApp() {
        initializeTeamAndApp();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName,teamName);

        applicationDetailPage.clickEditDeleteBtn()
                .attachTag("PCI")
                .clickModalSubmit();

        TagDetailPage tagDetailPage = applicationDetailPage.clickTagsLink()
                .clickTagName("PCI");

        assertTrue("PCI tag was not attached to application", tagDetailPage.isTagAttachedtoApp(appName));
    }

    @Test
    public void testManuallyAttachHipaaTagToApp() {
        initializeTeamAndApp();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName,teamName);

        applicationDetailPage.clickEditDeleteBtn()
                .attachTag("HIPAA")
                .clickModalSubmit();

        TagDetailPage tagDetailPage = applicationDetailPage.clickTagsLink()
                .clickTagName("HIPAA");

        assertTrue("HIPAA tag was not attached to application", tagDetailPage.isTagAttachedtoApp(appName));
    }

    @Test
    public void testPciTagPresence() {
        loginPage.defaultLogin()
                .clickTagsLink();

        assertTrue("PCI Tag not on page", driver.findElement(By.linkText("PCI")).isDisplayed());
    }

    @Test
    public void testHipaaTagPresence() {
        loginPage.defaultLogin()
                .clickTagsLink();

        assertTrue("HIPAA Tag not on page", driver.findElement(By.linkText("HIPAA")).isDisplayed());
    }

    @Test
    public void testIssue842Part1() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .expandTeamApplicationFilter("trendingFilterDiv");

        assertTrue("Team name is displayed and should not be",
                !analyticsPage.isTeamDisplayedinTeamDropDown(hiddenTeam,"trendingFilterDiv"));
    }

    @Test
    public void testIssue842Part2() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();
        String hiddenApp = createApplication(hiddenTeam);

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .expandTeamApplicationFilter("trendingFilterDiv");

        assertTrue("Team/App name is displayed and should not be",
                !analyticsPage.isAppDisplayedinAppDropDown(hiddenTeam, hiddenApp, "trendingFilterDiv"));
    }

    @Test
    public void testIssue845Part1() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilter("snapshotFilterDiv");

        assertTrue("Team name is displayed and should not be",
                !analyticsPage.isTeamDisplayedinTeamDropDown(hiddenTeam,"snapshotFilterDiv"));
    }

    @Test
    public void testIssue845Part2() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();
        String hiddenApp = createApplication(hiddenTeam);

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilter("snapshotFilterDiv");

        assertTrue("Team/App name is displayed and should not be",
                !analyticsPage.isAppDisplayedinAppDropDown(hiddenTeam, hiddenApp, "snapshotFilterDiv"));
    }

    @Test
    public void testIssue841Part1() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab()
                .expandTeamApplicationFilter("vulnSearchDiv");

        assertTrue("Team name is displayed and should not be",
                !analyticsPage.isTeamDisplayedinTeamDropDown(hiddenTeam,"vulnSearchDiv"));
    }

    @Test
    public void testIssue841Part2() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();
        String hiddenApp = createApplication(hiddenTeam);

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        AnalyticsPage analyticsPage = loginPage.login(user, "TestPassword")
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab()
                .expandTeamApplicationFilter("vulnSearchDiv");

        assertTrue("Team/App name is displayed and should not be",
                !analyticsPage.isAppDisplayedinAppDropDown(hiddenTeam, hiddenApp, "vulnSearchDiv"));
    }
}