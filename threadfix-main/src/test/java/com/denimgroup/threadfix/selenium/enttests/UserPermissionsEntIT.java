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
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserPermissionsPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
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
    public void addPermissionsTest() {
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
    public void addPermissionsValidation() {
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
    public void duplicatePermissionsValidation() {
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

    //TODO finish up
    @Test
    public void deletePermissions() {
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
}
