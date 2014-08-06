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
import org.apache.bcel.generic.DUP;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@Category(EnterpriseTests.class)
public class UserPermissionsEntIT extends BaseIT{

    @Test
    public void navigationTest() {
        String userName = getRandomString(8);
        String password = getRandomString(15);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName);

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

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
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
        String password = getRandomString(15);
        String role1 = "Administrator";
        String role2 = "User";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .toggleAllApps()
                .setApplicationRole(appName1, role1)
                .setApplicationRole(appName2, role2)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly for the first application.",
                userPermissionsPage.isPermissionPresent(teamName, appName1, role1));

        assertTrue("Permissions were not added properly for the second application",
                userPermissionsPage.isPermissionPresent(teamName, appName2, role2));
    }

    @Test
    public void addPermissionsFieldValidation() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        String userName = getRandomString(8);
        String password = getRandomString(15);

        String noTeamRoleError = "Failure. Message was : You must pick a Role.";
        String noApplicationRoleSelectedError = "Failure. Message was : You must select at least one application.";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
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
        String password = getRandomString(15);
        String role = "Administrator";

        String duplicateErrorMessage = "Failure. Message was : That team / role combo already exists for this user.";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
                .clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(role)
                .clickModalSubmit();

        assertTrue("Permissions were not added properly.",
                userPermissionsPage.isPermissionPresent(teamName, "all", role));

        userPermissionsPage.clickAddPermissionsLink()
                .setTeam(teamName)
                .setTeamRole(role)
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
        String password = getRandomString(15);
        String role1 = "Administrator";
        String role2 = "User";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
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
        String password = getRandomString(15);
        String role = "Administrator";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
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
        String password = getRandomString(15);
        String role = "Administrator";

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
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

        userIndexPage = teamDetailPage.logout()
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

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .setPermissionValue(deniedPermission,false)
                .clickModalSubmit();



    }
}
