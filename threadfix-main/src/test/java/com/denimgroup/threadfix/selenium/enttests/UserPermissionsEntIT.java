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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class UserPermissionsEntIT extends BaseDataTest{

    @Test
    public void testBasicNavigation() {
        String userName = createRegularUser();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName);

        assertTrue("Team Role Configuration is not present.", userIndexPage.isTeamRoleConfigurationPresent());
        assertTrue("Application role configuration is not present.", userIndexPage.isApplicationRoleConfigurationPresent());
    }

    @Test
    public void testAddAllPermissions() {
        String teamName = createTeam();
        String userName = createRegularUser();

        String role = "Administrator";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName)
                .setTeamRole(role)
                .clickSaveMap();

        assertTrue("Permissions were not added properly.",
                userIndexPage.isTeamRolePresent(teamName, role));
    }

    @Test
    public void testAddPermissionsFieldValidation() {
        initializeTeamAndApp();

        String userName = createRegularUser();

        String noTeamRoleError = "You must pick a Role.";
        String noApplicationRoleSelectedError = "You must set at least one role.";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName)
                .clickSaveMap();

        assertTrue("Error message indicating a role must be selected is not present.",
                userIndexPage.isErrorPresent(noTeamRoleError));

        userIndexPage.clickCloseButton()
                .clickAddApplicationRole()
                .clickSaveMap();

        assertTrue("Error message indicating an application must be selected is present.",
                userIndexPage.isErrorPresent(noApplicationRoleSelectedError));

    }

    @Test
    public void testDuplicatePermissionsFieldValidation() {
        initializeTeamAndApp();

        String userName = createRegularUser();
        String teamRole = "Administrator";

        String duplicateErrorMessage = "That team / role combination already exists for this user.";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName)
                .setTeamRole(teamRole)
                .clickSaveMap();

        assertTrue("Permissions were not added properly.",
                userIndexPage.isTeamRolePresent(teamName, teamRole));

        userIndexPage.clickAddTeamRole()
                .setTeam(teamName)
                .setTeamRole(teamRole)
                .clickSaveMap();

        //Runtime Fix
        sleep(5000);

        assertTrue("Duplicate team/role combinations should not be allowed.",
                userIndexPage.isErrorPresent(duplicateErrorMessage));
    }

    @Test
    public void testPermissionUsageValidation() {
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String role1 = "Administrator";
        String role2 = "User";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName1)
                .setTeamRole(role1)
                .clickSaveMap();

        assertTrue("Permissions were not added properly.",
                userIndexPage.isTeamRolePresent(teamName1, role1));

        userIndexPage.clickAddTeamRole()
                .setTeam(teamName2)
                .setTeamRole(role2)
                .clickSaveMap();

        assertTrue("Permissions were not added properly.",
                userIndexPage.isTeamRolePresent(teamName2, role2));

        TeamIndexPage teamIndexPage = userIndexPage.logout()
                .login(userName, testPassword)
                .clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName1);

        assertTrue("User is unable to add an application to the team.", teamDetailPage.isAddAppBtnPresent());

        teamDetailPage.clickAddApplicationButton()
                .setApplicationInfo(appName,"http://test.com", "Medium")
                .clickModalSubmit();

        assertTrue("Application was not present on the team's detail page.", teamDetailPage.isAppPresent(appName));

        teamDetailPage = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName2);

        assertFalse("User is able to add an application to the team", teamDetailPage.isAddAppBtnPresent());
    }

    @Test
    public void testDeleteTeamRole() {
        initializeTeamAndApp();

        String userName = createRegularUser();
        String role = "Administrator";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName)
                .setTeamRole(role)
                .clickSaveMap();

        assertTrue("Permissions were not added properly.",
                userIndexPage.isTeamRolePresent(teamName, role));

        userIndexPage.deleteTeamRole(teamName, role);

        assertFalse("Permissions were not properly deleted.",
                userIndexPage.isTeamRolePresent(teamName, role));
    }

    @Test
    public void testDeleteRolesValidation() {
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String role = "Administrator";

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(userName)
                .clickAddTeamRole()
                .setTeam(teamName1)
                .setTeamRole(role)
                .clickSaveMap();

        userIndexPage.clickAddTeamRole()
                .setTeam(teamName2)
                .setTeamRole(role)
                .clickSaveMap();

        TeamIndexPage teamIndexPage = userIndexPage.logout()
                .login(userName, testPassword)
                .clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName1);

        assertTrue("Add application button is not present.", teamDetailPage.isAddAppBtnPresent());

        teamDetailPage.clickAddApplicationButton()
                .setApplicationInfo(appName, "http://test.com", "Medium")
                .clickModalSubmit();

        assertTrue("User was unable to add an application.", teamDetailPage.isAppPresent(appName));

        userIndexPage = teamDetailPage.logout()
                .defaultLogin()
                .clickManageUsersLink();

        userIndexPage = userIndexPage.clickUserLink(userName)
                .deleteTeamRole(teamName1, role);

        teamIndexPage = userIndexPage.logout()
                .login(userName, testPassword)
                .clickOrganizationHeaderLink();

        assertFalse("User should not be able to view this team.", teamIndexPage.isTeamPresent(teamName1));
    }

    @Test
    public void testPermissionsAlphabeticalOrder() {
        String firstTeamName = "A" + getName();
        DatabaseUtils.createTeam(firstTeamName);
        String firstAppName = createApplication(firstTeamName);

        String secondTeamName = "Z" + getName();
        DatabaseUtils.createTeam(secondTeamName);
        String secondAppName = createApplication(secondTeamName);

        String userName = createRegularUser();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink();

        userIndexPage.clickUserLink(userName)
                .clickAddTeamRole()
                .expandTeamName();

        assertTrue("The applications are not sorted", userIndexPage.compareOrderOfSelector(firstTeamName, secondTeamName));
    }

    @Ignore
    @Test
    public void testReportPermissions() {
        initializeTeamAndAppWithIbmScan();

        String userName = getRandomString(8);

        String roleName = getName();
        String deniedPermission = "canGenerateReports";

        //DatabaseUtils.createRole(roleName);

        RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .setPermissionValue(deniedPermission,false)
                .clickModalSubmit();
    }

    @Test
    public void testViewErrorLogPermission() {
        createRestrictedUser("canViewErrorLogs");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

       assertFalse("View Error Log wasn't gone", dashboardPage.isElementPresent("viewLogsLink"));
    }

    @Test
    public void testUploadScanPermission() {
        initializeTeamAndApp();

        createRestrictedUser("canUploadScans");

        TeamIndexPage teamIndexPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("Upload Button is Available", teamIndexPage.isUploadButtonPresent(teamName, appName));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickApplicationName(teamName, appName)
                .clickActionButton();

        assertFalse("Upload Link is Available", applicationDetailPage.isElementPresent("uploadScanModalLink"));
    }

    @Test
    public void testSubmitDefectsPermission() {
        initializeTeamAndAppWithIbmScan();

        createRestrictedUser("canSubmitDefects");

        String newDefectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login(userName, testPassword)
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .setName(newDefectTrackerName)
                .setURL(BUGZILLA_URL)
                .setType(defectTrackerType)
                .clickSaveDefectTracker();

        ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .addDefectTracker(newDefectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME)
                .clickVulnerabilitiesActionButton();

        assertFalse("Submit Defect is Present", applicationDetailPage.isElementPresent("submitDefectButton"));
    }

    @Test
    public void testManageVulnerabilityFilters() {
        initializeTeamAndAppWithIbmScan();

        createRestrictedUser("canManageVulnFilters");

        CustomizeVulnerabilityTypesPage customizeVulnerabilityTypesPage = loginPage.login(userName, testPassword)
                .clickCustomizeThreadFixVulnerabilityTypesLink();

        assertTrue("Access Denied Page is not showing", customizeVulnerabilityTypesPage.isAccessDenied());

        customizeVulnerabilityTypesPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickActionButton();

        assertFalse("Close Vulnerability button is available",
                customizeVulnerabilityTypesPage.isElementPresent("editVulnerabilityFiltersButton"));
    }

    @Test
    public void testModifyVulnerabilitiesPermission() {
        initializeTeamAndAppWithIbmScan();

        createRestrictedUser("canModifyVulnerabilities");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickVulnerabilitiesActionButton();

        assertFalse("Close Vulnerabilities Link is available",
                applicationDetailPage.isElementPresent("closeVulnsButton"));

        assertFalse("Mark as False Positive Link is available",
                applicationDetailPage.isElementPresent("markFalsePositivesButton"));

        FindingDetailPage findingDetailPage = applicationDetailPage.clickScansTab()
                .clickViewScan()
                .clickViewFinding();

        assertFalse("Merge With Other Findings Button is available",
                findingDetailPage.isLinkPresent("Merge with Other Findings"));

        findingDetailPage.clickViewVulnerabilityLimitedPermission();

        assertFalse("Close Vulnerability button is available",
                findingDetailPage.isElementPresent("closeVulnerabilityLink"));
        assertFalse("Merge With Other Findings Button is available",
                findingDetailPage.isElementPresent("markFalsePositiveLink"));
        assertFalse("Add File Button is present",
                findingDetailPage.isElementPresent("uploadDocVulnModalLink"));
        assertFalse("Merge With Other Findings Button is available",
                findingDetailPage.isLinkPresent("Add Comment"));
    }

    @Ignore
    @Test
    public void testManageWAFsPermission() {
        /* This test is throwing JavaScript errors when
        attempting to handle JavaScript alert message.
        Similar error have appeared online.
         */
        initializeTeamAndAppWithIbmScan();

        String wafName = getName();
        DatabaseUtils.createWaf(wafName, "Snort" );

        createRestrictedUser("canManageWafs");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf();
            assertTrue("Creating WAF was still allowed.", applicationDetailPage.isWafCreationDenied());
        } else {
            assertTrue("Creating WAF was still allowed.", applicationDetailPage.isWAFAddButtonPresent());
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickCloseModalButton()
                .clickEditDeleteBtn()
                .clickSetWaf()
                .addWaf(wafName)
                .saveWafAdd()
                .clickWafNameLink();

        wafIndexPage.clickGenerateWafRulesButton();

        assertTrue("Generating WAf Rules wasn't applied",
                wafIndexPage.isDownloadWafRulesDisplay());

        wafIndexPage.clickConfigTab();

        assertFalse("Waf Link is Present", applicationDetailPage.isElementPresent("wafsLink"));
    }

    @Test
    public void testManageUsersPermission() {
        createRestrictedUser("canManageUsers");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageUsersLink"));
    }

    @Test
    public void testManageTeamsPermission() {
        String teamName = createTeam();

        createRestrictedUser("canManageTeams");

        TeamDetailPage teamDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickActionButtonWithoutEditButton();

        assertFalse("Team Edit/Delete Button is available", teamDetailPage.isElementPresent("teamModalButton"));
    }

    @Test
    public void testManageRoles() {
        createRestrictedUser("canManageRoles");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageRolesLink"));
    }

    @Test
    public void testManageSystemSettingsPermission() {
        createRestrictedUser("canManageSystemSettings");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("configureDefaultsLink"));
    }

    @Test
    public void testManageScanAgentsPermission() {
        initializeTeamAndApp();

        createRestrictedUser("canManageScanAgents");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName);

        assertFalse("Scan Agent Tab is Available", applicationDetailPage.isLinkPresent("0 Scan Agent Tasks"));
        assertFalse("Scheduled Scans Tab Available", applicationDetailPage.isLinkPresent("0 Scheduled Scans"));

        applicationDetailPage.clickConfigTab();

        assertFalse("Scan  Agent Tasks Link is Available", applicationDetailPage.isElementPresent("scanQueueLink"));
    }

    @Test
    public void testManageRemoteProvidersPermission() {
        createRestrictedUser("canManageRemoteProviders");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Remote Providers Link is Present", dashboardPage.isElementPresent("remoteProvidersLink"));
    }

    @Test
    public void testManageApplicationsPermission() {
        initializeTeamAndApp();

        createRestrictedUser("canManageApplications");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickActionButton();

        assertFalse("Edit/Delete Button wasn't gone",
                applicationDetailPage.isElementPresent("editApplicationModalButton"));
        assertTrue("Detail Link wasn't created", applicationDetailPage.isDetailLinkDisply());
    }

    @Test
    public void testManageApiKeysPermission() {
        createRestrictedUser("canManageApiKeys");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("API keys Link is Present", dashboardPage.isApiKeysLinkPresent());
    }

    @Test
    public void testGenerateWafRulesPermission() {
        initializeTeamAndAppWithIbmScan();

        createRestrictedUser("canGenerateWafRules");

        String wafName = getName();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .clickSetWaf();

        if (applicationDetailPage.isWafPresent()) {
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWafButton();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWafButton();
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafNameLink();

        assertFalse("The waf was still present after attempted deletion.",
                wafIndexPage.isGenerateWafRulesButtonPresent());
    }

    @Test
    public void testGenerateReportsPermission() {
        initializeTeamAndAppWithWebInspectScan();

        createRestrictedUser("canGenerateReports");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        assertFalse("Left Report is still Present", dashboardPage.isLeftReportLinkPresent());
        assertFalse("Right Report is still Present", dashboardPage.isRightReportLinkPresent());

        TeamIndexPage teamIndexPage = dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        teamIndexPage.waitForPieWedge(teamName, "Critical");

        assertTrue("The Chart is still available", teamIndexPage.isGraphWedgeDisplayed(teamName, "Info") &&
                teamIndexPage.isGraphWedgeDisplayed(teamName, "Low") &&
                teamIndexPage.isGraphWedgeDisplayed(teamName, "Medium") &&
                teamIndexPage.isGraphWedgeDisplayed(teamName, "High") &&
                teamIndexPage.isGraphWedgeDisplayed(teamName, "Critical"));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName);

        assertFalse("Left Report is still Present", applicationDetailPage.isLeftReportLinkPresent());
        assertFalse("Right Report is still Present", applicationDetailPage.isRightReportLinkPresent());

        assertFalse("Analytics Tab is still available", applicationDetailPage.isElementPresent("tab-reports"));
    }

    @Test
    public void testPermissionWithNoTeam() {
        DashboardPage dashboardPage = loginPage.defaultLogin();

        if (dashboardPage.isViewMoreLinkPresent()) {

            UserIndexPage userIndexPage = dashboardPage.clickManageUsersLink()
                    .clickUserLink("user");
            assertFalse("user Permission wasn't available", userIndexPage.isAddTeamRoleButtonDisabled());
        } else {
            UserIndexPage userIndexPage = dashboardPage.clickManageUsersLink()
                    .clickUserLink("user");

            assertTrue("Add Permission Button is Clickable", userIndexPage.isAddTeamRoleButtonDisabled());
        }
    }

    @Test
    public void testManageApplicationPermissionScanAgent() {
        initializeTeamAndApp();
        String scanner = "OWASP Zed Attack Proxy";

        createRestrictedUser("canManageApplications");

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .setScanQueueType(scanner)
                .submitScanQueue();

        LoginPage loginPage = applicationDetailPage.logout();

        ScanAgentTasksPage scanAgentTasksPage = loginPage.login(userName, testPassword)
                .clickScanAgentTasksLink()
                .clickDeleteScan(0);

        assertTrue("Scan wasn't deleted", scanAgentTasksPage.successAlert()
                .contains("One time OWASP Zed Attack Proxy Scan has been deleted from Scan Agent queue"));
    }

    @Test
    public void testAddAppRole() {
        String teamName1 = createTeam();
        String appName1 = createApplication(teamName1);
        String teamName2 = createTeam();
        String appName2 = createApplication(teamName2);
        String user = createRegularUser();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(user)
                .clickAddApplicationRole()
                .setTeam(teamName1)
                .setApplicationRole(appName1, "User")
                .clickSaveMap();

        boolean checkPermissions1 = userIndexPage.isApplicationRolePresent(teamName1, appName1, "User");

        assertTrue("Failed to add permissions separate from Global permissions", checkPermissions1);

        userIndexPage.clickAddApplicationRole()
                .setTeam(teamName2)
                .setApplicationRole(appName2, "User")
                .clickSaveMap();

        boolean checkPermissions2 = userIndexPage.isApplicationRolePresent(teamName2, appName2, "User");

        assertTrue("Failed to add more permissions", checkPermissions2);
    }

    @Test
    public void testEditPermissions() {
        initializeTeamAndApp();

        String role1 = "User";
        String role2 = "Administrator";
        String user = createRegularUser();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickUserLink(user)
                .clickAddApplicationRole()
                .setTeam(teamName)
                .setApplicationRole(appName,role1)
                .clickSaveMap();

        userIndexPage.editSpecificPermissions(teamName, appName, role1)
                .setApplicationRole(appName, role2)
                .clickSaveEdits();

        assertTrue("Could not edit permissions", userIndexPage.isApplicationRolePresent(teamName, appName, role2));
    }

    @Test
    public void testManageTagsPermission() {
        createRestrictedUser("canManageTags");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertTrue("Manage tags permission not added", driver.findElements(By.id("tagsLink")).isEmpty());
    }
}
