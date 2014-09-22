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
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class UserPermissionsEntIT extends BaseIT{

    private static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
    private static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
    private static final String BUGZILLA_URL = System.getProperty("BUGZILLA_URL");

    @Test
    public void navigationTest() {
        String userName = getRandomString(8);

        DatabaseUtils.createUser(userName);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickEditPermissions(userName);

        assertTrue("Unable to navigate to users permissions page.", userPermissionsPage.isUserNamePresent(userName));

        userPermissionsPage.clickAddPermissionsLink();

        assertTrue("Add permissions modal is not present.", userPermissionsPage.isPermissionsModalPresent());
    }

    @Test
    public void addAllPermissionsTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String userName = getRandomString(8);
        String password = getRandomString(15);
        String role = "Administrator";

        DatabaseUtils.createUser(userName, role);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
    public void addAppPermissionsTest() {
        String teamName = getRandomString(8);
        String appName1 = getRandomString(8);
        String appName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName1);
        DatabaseUtils.createApplication(teamName, appName2);

        String userName = getRandomString(8);
        String appRole1 = "Administrator";
        String appRole2 = "User";

        DatabaseUtils.createUser(userName);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .toggleAllApps()
                .setApplicationRole(appName1, appRole1)
                .setApplicationRole(appName2, appRole2)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly for the first application.",
                userPermissionsPage.isPermissionPresent(teamName, appName1, appRole1));

        assertTrue("Permissions were not added properly for the second application",
                userPermissionsPage.isPermissionPresent(teamName, appName2, appRole2));
    }

    @Test
    public void addPermissionsFieldValidation() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String userName = getRandomString(8);

        DatabaseUtils.createUser(userName);

        String noTeamRoleError = "Failure. Message was : You must pick a Role.";
        String noApplicationRoleSelectedError = "Failure. Message was : You must select at least one application.";

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String userName = getRandomString(8);
        String teamRole = "Administrator";

        DatabaseUtils.createUser(userName);

        String duplicateErrorMessage = "Failure. Message was : That team / role combo already exists for this user.";

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);

        String userName = getRandomString(8);
        String password = "TestPassword";
        String role1 = "Administrator";
        String role2 = "User";

        DatabaseUtils.createUser(userName);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String userName = getRandomString(8);
        String role = "Administrator";

        DatabaseUtils.createUser(userName);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);

        String userName = getRandomString(8);
        String password = "TestPassword";
        String role = "Administrator";

        DatabaseUtils.createUser(userName);

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
                .login("user", "password")
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
        String firstTeamName = "A" + getRandomString(8);
        String firstAppName = getRandomString(8);

        DatabaseUtils.createTeam(firstTeamName);
        DatabaseUtils.createApplication(firstTeamName, firstAppName);

        String secondTeamName = "Z" + getRandomString(8);
        String secondAppName = getRandomString(8);

        DatabaseUtils.createTeam(secondTeamName);
        DatabaseUtils.createApplication(secondTeamName, secondAppName);

        String userName = getRandomString(8);

        DatabaseUtils.createUser(userName);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .expandTeamName();

        assertTrue("The applications are sorted",userPermissionsPage.compareOrderOfSelector(firstTeamName, secondTeamName));
    }

    @Ignore
    @Test
    public void reportPermissionsTest() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String userName = getRandomString(8);
        String password = getRandomString(15);

        String roleName = getRandomString(8);
        String deniedPermission = "canGenerateReports";

        //DatabaseUtils.createRole(roleName);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .setPermissionValue(deniedPermission,false)
                .clickModalSubmit();
    }

    @Test
    public void checkViewErrorLogPermission() {
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canViewErrorLogs")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

       assertFalse("View Error Log wasn't gone", dashboardPage.isElementPresent("viewLogsLink"));
    }

    @Test
    public void checkUploadScanPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canUploadScans")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        TeamIndexPage teamIndexPage = loginPage.login(userName, "TestPassword")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("Upload Button is Available", teamIndexPage.isUploadButtonPresent(teamName, appName));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickApplicationName(appName)
                .clickActionButton();

        assertFalse("Upload Link is Available", applicationDetailPage.isElementPresent("uploadScanModalLink"));
    }

    @Test
    public void checkSubmitDefectsPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        String newDefectTrackerName = "testCreateDefectTracker"+ getRandomString(3);
        String defectTrackerType = "Bugzilla";

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canSubmitDefects")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.login(userName, "TestPassword")
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
                .addDefectTracker(newDefectTrackerName, BUGZILLA_USERNAME, BUGZILLA_PASSWORD, "QA Testing")
                .clickVulnerabilitiesActionButton();

        assertFalse("Submit Defect is Present", applicationDetailPage.isElementPresent("submitDefectButton"));
    }

    @Test
    public void checkManageVulnerabilityFilters() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName,appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageVulnFilters")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        FilterPage applicationFilterPage = loginPage.login(userName, "TestPassword")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canModifyVulnerabilities")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);
        String wafName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.createWaf(wafName, "Snort" );

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageWafs")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
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
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canManageUsers")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", rolesIndexPage.isElementPresent("manageUsersLink"));
    }

    @Test
    public void checkManageTeamsPermission() {
        String teamName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageTeams")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        TeamDetailPage teamDetailPage = loginPage.login(userName, "TestPassword")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickActionButtonWithoutEditButton();

        assertFalse("Team Edit/Delete Button is available", teamDetailPage.isElementPresent("teamModalButton"));
    }

    @Test
    public void checkManageRoles() {
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canManageRoles")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", rolesIndexPage.isElementPresent("manageRolesLink"));
    }

    @Test
    public void checkManageSystemSettingsPermission() {
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canManageSystemSettings")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", rolesIndexPage.isElementPresent("configureDefaultsLink"));
    }

    @Test
    public void checkManageScanAgentsPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageScanAgents")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
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
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canManageRemoteProviders")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Remote Providers Link is Present", rolesIndexPage.isElementPresent("remoteProvidersLink"));
    }

    @Test
    public void checkManageApplicationsPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageApplications")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
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
        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canManageApiKeys")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("API keys Link is Present", dashboardPage.isElementPresent("apiKeysLink"));
    }

    @Test
    public void checkGenerateWAFRulesPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));


        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        String wafName = "testDeleteWaf" + getRandomString(3);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canGenerateWafRules")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String roleName = getRandomString(8);
        String userName = getRandomString(8);

        RolesIndexPage rolesIndexPage = this.loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false, "canGenerateReports")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickAddNewUserBtn();

        LoginPage loginPage = userIndexPage.clickLogOut();

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        assertFalse("Left Report is still Present", dashboardPage.isLeftReportLinkPresent());
        assertFalse("Right Report is still Present", dashboardPage.isRightReportLinkPresent());

        TeamIndexPage teamIndexPage = dashboardPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);

        assertFalse("The Chart still available",teamIndexPage.isGraphDisplayed(teamName));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickViewAppLink(appName, teamName);

        assertFalse("Left Report is still Present", applicationDetailPage.isLeftReportLinkPresent());
        assertFalse("Right Report is still Present", applicationDetailPage.isRightReportLinkPresent());

        assertFalse("Analytics Tab is still available", applicationDetailPage.isElementPresent("tab-reports"));
    }
}
