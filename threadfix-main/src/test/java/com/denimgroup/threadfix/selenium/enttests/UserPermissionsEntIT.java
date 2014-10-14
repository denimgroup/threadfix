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

    private String roleName;
    private String userName;

    public void createRestrictedUser(String permission) {
        if (permission != null) {
            roleName = createRole();
            DatabaseUtils.removePermission(roleName, permission);

            userName = createSpecificRoleUser(roleName);
        } else {
            throw new RuntimeException("Permission required to create a restricted user.");
        }
    }

    @Test
    public void navigationTest() {
        String userName = createRegularUser();

        UserPermissionsPage userPermissionsPage = loginPage.login("user", "password")
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
        String teamName = createTeam();
        String appName1 = createApplication(teamName);
        String appName2 = createApplication(teamName);

        String userName = createRegularUser();
        String appRole1 = "Administrator";
        String appRole2 = "User";

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();
        String teamRole = "Administrator";

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
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String password = "TestPassword";
        String role1 = "Administrator";
        String role2 = "User";

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        String userName = createRegularUser();
        String role = "Administrator";

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
        String teamName1 = createTeam();
        String teamName2 = createTeam();
        String appName = getName();

        String userName = createRegularUser();
        String password = "TestPassword";
        String role = "Administrator";

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
        String firstTeamName = "A" + getName();
        DatabaseUtils.createTeam(firstTeamName);
        String firstAppName = createApplication(firstTeamName);

        String secondTeamName = "Z" + getName();
        DatabaseUtils.createTeam(secondTeamName);
        String secondAppName = createApplication(secondTeamName);

        String userName = createRegularUser();

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String userName = getRandomString(8);
        String password = getRandomString(15);

        String roleName = getName();
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
        createRestrictedUser("canViewErrorLogs");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

       assertFalse("View Error Log wasn't gone", dashboardPage.isElementPresent("viewLogsLink"));
    }

    @Test
    public void checkUploadScanPermission() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        createRestrictedUser("canUploadScans");

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        createRestrictedUser("canSubmitDefects");

        String newDefectTrackerName = getName();
        String defectTrackerType = "Bugzilla";

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        createRestrictedUser("canManageVulnFilters");

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        createRestrictedUser("canModifyVulnerabilities");

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
        String wafName = getName();
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.createWaf(wafName, "Snort" );

        createRestrictedUser("canManageWafs");

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
        createRestrictedUser("canManageUsers");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageUsersLink"));
    }

    @Test
    public void checkManageTeamsPermission() {
        String teamName = createTeam();

        createRestrictedUser("canManageTeams");

        TeamDetailPage teamDetailPage = loginPage.login(userName, "TestPassword")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickActionButtonWithoutEditButton();

        assertFalse("Team Edit/Delete Button is available", teamDetailPage.isElementPresent("teamModalButton"));
    }

    @Test
    public void checkManageRoles() {
        createRestrictedUser("canManageRoles");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("manageRolesLink"));
    }

    @Test
    public void checkManageSystemSettingsPermission() {
        createRestrictedUser("canManageSystemSettings");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Users Link is Present", dashboardPage.isElementPresent("configureDefaultsLink"));
    }

    @Test
    public void checkManageScanAgentsPermission() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        createRestrictedUser("canManageScanAgents");

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
        createRestrictedUser("canManageRemoteProviders");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("Manage Remote Providers Link is Present", dashboardPage.isElementPresent("remoteProvidersLink"));
    }

    @Test
    public void checkManageApplicationsPermission() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        createRestrictedUser("canManageApplications");

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
        createRestrictedUser("canManageApiKeys");

        DashboardPage dashboardPage = loginPage.login(userName, "TestPassword");

        dashboardPage.clickConfigTab();

        assertFalse("API keys Link is Present", dashboardPage.isElementPresent("apiKeysLink"));
    }

    @Test
    public void checkGenerateWAFRulesPermission() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        createRestrictedUser("canGenerateWafRules");

        String wafName = getName();

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        createRestrictedUser("canGenerateReports");

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

    @Test
    public void testPermissionWithNoTeam() {
        DashboardPage dashboardPage = loginPage.login("user", "password");

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
        String teamName = createTeam();
        String appName = createApplication(teamName);

        createRestrictedUser("canManageApplications");

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScanAgentTasksTab(0)
                .clickAddNewScanTask()
                .submitScanQueue();

        LoginPage loginPage = applicationDetailPage.logout();

        ScanAgentTasksPage scanAgentTasksPage = loginPage.login(userName, "TestPassword")
                .clickScanAgentTasksLink()
                .clickDeleteScan(0);

        assertTrue("Scan wasn't deleted", scanAgentTasksPage.successAlert()
                .contains("One time OWASP Zed Attack Proxy Scan has been deleted from Scan Agent queue"));
    }
}
