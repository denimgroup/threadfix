////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
    public void navigationTest() {
        String userName = createRegularUser();

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName);

        assertTrue("Unable to navigate to users permissions page.", userPermissionsPage.isUserNamePresent(userName));

        userPermissionsPage.clickAddPermissionsLink();

        assertTrue("Add permissions modal is not present.", userPermissionsPage.isPermissionsModalPresent());
    }

    @Test
    public void addAllPermissionsTest() {
        String teamName = createTeam();
        String userName = createRegularUser();

        String role = "Administrator";

        DatabaseUtils.createUser(userName, role);

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(role)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName, "all", role));
    }

    @Test
    public void addPermissionsFieldValidation() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();

        String noTeamRoleError = "Failure. Message was : You must pick a Role.";
        String noApplicationRoleSelectedError = "Failure. Message was : You must select at least one application.";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .clickModalSubmitInvalid();

        assertTrue("Error message indicating a role must be selected is not present.",
                userPermissionsPage.isErrorPresent(noTeamRoleError));

        userPermissionsPage.toggleAllApps()
                .clickModalSubmitInvalid();

        assertTrue("Error message indicating an application must be selected is present.",
                userPermissionsPage.isErrorPresent(noApplicationRoleSelectedError));

    }

    @Test
    public void duplicatePermissionsFieldValidation() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();
        String teamRole = "Administrator";

        String duplicateErrorMessage = "Failure. Message was : That team / role combo already exists for this user.";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(teamRole)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName, "all", teamRole));

        userPermissionsPage.clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(teamRole)
                .clickModalSubmitInvalid();

        assertTrue("Duplicate team/role combinations should not be allowed.",
                userPermissionsPage.isErrorPresent(duplicateErrorMessage));
    }

    @Test
    public void permissionUsageValidation() {
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String password = "TestPassword";
        String role1 = "Administrator";
        String role2 = "User";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName1)
                .setTeamRole(role1)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName1, "all", role1));

        userPermissionsPage.clickAddPermissionsLink()
                .setTeam(teamName2)
                .setTeamRole(role2)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName2, "all", role2));

        TeamIndexPage teamIndexPage = userPermissionsPage.logout()
                .login(userName, password)
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
    public void deletePermissionsTest() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();
        String role = "Administrator";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(role)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName, "all", role));

        userPermissionsPage.clickDeleteButton(teamName, "all", role);

        assertFalse("Permissions were not properly deleted.",
                userPermissionsPage.isPermissionPresent(teamName, "all", role));
    }

    @Test
    public void deletePermissionsValidation() {
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String password = "TestPassword";
        String role = "Administrator";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName1)
                .setTeamRole(role)
                .clickModalSubmit();

        userPermissionsPage.clickAddPermissionsLink()
                .setTeam(teamName2)
                .setTeamRole(role)
                .clickModalSubmit();

        TeamIndexPage teamIndexPage = userPermissionsPage.logout()
                .login(userName, password)
                .clickOrganizationHeaderLink();

        TeamDetailPage teamDetailPage = teamIndexPage.clickViewTeamLink(teamName1);

        assertTrue("Add application button is not present.", teamDetailPage.isAddAppBtnPresent());

        teamDetailPage.clickAddApplicationButton()
                .setApplicationInfo(appName, "http://test.com", "Medium")
                .clickModalSubmit();

        assertTrue("User was unable to add an application.", teamDetailPage.isAppPresent(appName));

        UserIndexPage userIndexPage = teamDetailPage.logout()
                .defaultLogin()
                .clickManageUsersLink();

        userPermissionsPage = userIndexPage.clickEditPermissions(userName)
                .clickDeleteButton(teamName1, "all", role);

        teamIndexPage = userPermissionsPage.logout()
                .login(userName, password)
                .clickOrganizationHeaderLink();

        assertFalse("User should not be able to view this team.", teamIndexPage.isTeamPresent(teamName1));
    }

    @Test
    public void permissionsAlphabeticalOrderTest() {
        String firstTeamName = "A" + getName();
        DatabaseUtils.createTeam(firstTeamName);
        String firstAppName = createApplication(firstTeamName);

        String secondTeamName = "Z" + getName();
        DatabaseUtils.createTeam(secondTeamName);
        String secondAppName = createApplication(secondTeamName);

        String userName = createRegularUser();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .expandTeamName();

        assertTrue("The applications are sorted", userPermissionsPage.compareOrderOfSelector(firstTeamName, secondTeamName));
    }

    @Ignore
    @Test
    public void reportPermissionsTest() {
        initializeTeamAndAppWithIBMScan();

        String userName = getRandomString(8);
        String password = getRandomString(15);

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
    public void checkViewErrorLogPermission() {
        createRestrictedUser("canViewErrorLogs");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

       assertFalse("View Error Log wasn't gone", dashboardPage.isElementPresent("viewLogsLink"));
    }

    @Test
    public void checkUploadScanPermission() {
        initializeTeamAndApp();

        createRestrictedUser("canUploadScans");

        TeamIndexPage teamIndexPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("Upload Button is Available", teamIndexPage.isUploadButtonPresent(teamName, appName));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickApplicationName(appName)
                .clickActionButton();

        assertFalse("Upload Link is Available", applicationDetailPage.isElementPresent("uploadScanModalLink"));
    }

    @Test
    public void checkSubmitDefectsPermission() {
        initializeTeamAndAppWithIBMScan();

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
                .clickApplicationName(appName)
                .addDefectTracker(newDefectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME)
                .clickVulnerabilitiesActionButton();

        assertFalse("Submit Defect is Present", applicationDetailPage.isElementPresent("submitDefectButton"));
    }

    @Test
    public void checkManageVulnerabilityFilters() {
        initializeTeamAndAppWithIBMScan();

        createRestrictedUser("canManageVulnFilters");

        FilterPage applicationFilterPage = loginPage.login(userName, testPassword)
                .clickManageFiltersLink();

        assertTrue("Access Denied Page is not showing", applicationFilterPage.isAccessDenied());

         applicationFilterPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .clickActionButton();

        assertFalse("Close Vulnerability button is available",
                applicationFilterPage.isElementPresent("editVulnerabilityFiltersButton"));
    }

    @Test
    public void checkModifyVulnerabilitiesPermission() {
        initializeTeamAndAppWithIBMScan();

        createRestrictedUser("canModifyVulnerabilities");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
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

        findingDetailPage.clickViewVulnerability()
                .clickToggleMoreInfoButton();

        assertFalse("Close Vulnerability button is available",
                findingDetailPage.isElementPresent("closeVulnerabilityLink"));
        assertFalse("Merge With Other Findings Button is available",
                findingDetailPage.isElementPresent("markFalsePositiveLink"));
        assertFalse("Add File Button is present",
                findingDetailPage.isElementPresent("uploadDocVulnModalLink"));
        assertFalse("Merge With Other Findings Button is available",
                findingDetailPage.isLinkPresent("Add Comment"));
    }

    @Test
    public void checkManageWAFsPermission() {
        initializeTeamAndAppWithIBMScan();

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
            applicationDetailPage.clickCreateNewWaf()
                    .setWafName(wafName)
                    .clickCreateWAfButtom();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom();
        }

        assertTrue("Creating WAf is still Present", applicationDetailPage.applicationErrorMessage());

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
    public void checkManageUsersPermission() {
        createRestrictedUser("canManageUsers");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageUsersLink"));
    }

    @Test
    public void checkManageTeamsPermission() {
        String teamName = createTeam();

        createRestrictedUser("canManageTeams");

        TeamDetailPage teamDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickActionButtonWithoutEditButton();

        assertFalse("Team Edit/Delete Button is available", teamDetailPage.isElementPresent("teamModalButton"));
    }

    @Test
    public void checkManageRoles() {
        createRestrictedUser("canManageRoles");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageRolesLink"));
    }

    @Test
    public void checkManageSystemSettingsPermission() {
        createRestrictedUser("canManageSystemSettings");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("configureDefaultsLink"));
    }

    @Test
    public void checkManageScanAgentsPermission() {
        initializeTeamAndApp();

        createRestrictedUser("canManageScanAgents");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName);

        assertFalse("Scan Agent Tab is Available", applicationDetailPage.isLinkPresent("0 Scan Agent Tasks"));
        assertFalse("Scheduled Scans Tab Available", applicationDetailPage.isLinkPresent("0 Scheduled Scans"));

        applicationDetailPage.clickConfigTab();

        assertFalse("Scan  Agent Tasks Link is Available", applicationDetailPage.isElementPresent("scanQueueLink"));
    }

    @Test
    public void checkManageRemoteProvidersPermission() {
        createRestrictedUser("canManageRemoteProviders");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("Manage Remote Providers Link is Present", dashboardPage.isElementPresent("remoteProvidersLink"));
    }

    @Test
    public void checkManageApplicationsPermission() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        createRestrictedUser("canManageApplications");

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(appName)
                .clickActionButton();

        assertFalse("Edit/Delete Button wasn't gone",
                applicationDetailPage.isElementPresent("editApplicationModalButton"));
        assertTrue("Detail Link wasn't created", applicationDetailPage.isDetailLinkDisply());
    }

    @Test
    public void checkManageAPIKeysPermission() {
        createRestrictedUser("canManageApiKeys");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertFalse("API keys Link is Present", dashboardPage.isElementPresent("apiKeysLink"));
    }

    @Test
    public void checkGenerateWAFRulesPermission() {
        initializeTeamAndAppWithIBMScan();

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
                    .clickCreateWAfButtom();
        } else {
            applicationDetailPage.setWafName(wafName)
                    .clickCreateWAfButtom();
        }

        WafIndexPage wafIndexPage = applicationDetailPage.clickWafNameLink();

        assertFalse("The waf was still present after attempted deletion.",
                wafIndexPage.isGenerateWafRulesButtonPresent());
    }

    @Test
    public void checkGenerateReportsPermission() {
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

            UserPermissionsPage userPermissionsPage = dashboardPage.clickManageUsersLink()
                    .clickEditPermissions("user");
            assertTrue("user Permission wasn't available", userPermissionsPage.isAddPermissionClickable());
        } else {
            UserPermissionsPage userPermissionsPage1 = dashboardPage.clickManageUsersLink()
                    .clickEditPermissions("user");

            assertTrue("Add Permission Button is Clickable", userPermissionsPage1.isAddPermissionClickable());
            assertTrue("There is no Error Message Available",
                    userPermissionsPage1.errorAlert().contains("Cannot add permissions with no teams."));
        }
    }

    @Test
    public void testManageApplicationPermissionScanAgent() {
        initializeTeamAndApp();

        createRestrictedUser("canManageApplications");

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .submitScanQueue();

        LoginPage loginPage = applicationDetailPage.logout();

        ScanAgentTasksPage scanAgentTasksPage = loginPage.login(userName, testPassword)
                .clickScanAgentTasksLink()
                .clickDeleteScan(0);

        assertTrue("Scan wasn't deleted", scanAgentTasksPage.successAlert()
                .contains("One time OWASP Zed Attack Proxy Scan has been deleted from Scan Agent queue"));
    }

    @Test
    public void testUserPermissionsNavigation() {
        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions("user");

        assertTrue("Edit Permissions button didn't navigate correclty", userPermissionsPage.isUserNamePresent("user"));
    }

    @Test
    public void testAddAppPermissions() {
        String teamName1 = createTeam();
        String appName1 = createApplication(teamName1);
        String teamName2 = createTeam();
        String appName2 = createApplication(teamName2);

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions("user")
                .clickAddPermissionsLink()
                .setTeam(teamName1)
                .toggleAllApps()
                .setApplicationRole(appName1,"User")
                .clickModalSubmit();

        boolean checkPermissions1 = userPermissionsPage.isPermissionPresent(teamName1,appName1,"User");

        assertTrue("Failed to add permissions separate from Global permissions", checkPermissions1);

        userPermissionsPage.clickAddPermissionsLink()
                .setTeam(teamName2)
                .toggleAllApps()
                .setApplicationRole(appName2,"User")
                .clickModalSubmit();

        boolean checkPermissions2 = userPermissionsPage.isPermissionPresent(teamName2,appName2,"User");

        assertTrue("Failed to add more permissions", checkPermissions2);
    }

    @Test
    public void testEditPermissions() {
        initializeTeamAndApp();

        String role1 = "User";
        String role2 = "Administrator";

        UserPermissionsPage userPermissionsPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickEditPermissions("user")
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .toggleAllApps()
                .setApplicationRole(appName,role1)
                .clickModalSubmit();

        userPermissionsPage.editSpecificPermissions(teamName,appName,role1)
                .setApplicationRole(appName,role2)
                .clickModalSubmit();

        assertTrue("Could not edit permissions", userPermissionsPage.isPermissionPresent(teamName, appName, role2));
    }

    @Test
    public void testManageTagsPermission() {
        createRestrictedUser("canManageTags");

        DashboardPage dashboardPage = loginPage.login(userName, testPassword);

        dashboardPage.clickConfigTab();

        assertTrue("Manage tags permission not added", driver.findElements(By.id("tagsLink")).isEmpty());
    }
}
