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
import com.denimgroup.threadfix.selenium.pages.AnalyticsPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class TeamEntIT extends BaseDataTest {

    @Test
    public void viewBasicPermissibleUsers(){
        String teamName = getRandomString(8);
        String userName = getRandomString(8);
        String password = getRandomString(15);
        DatabaseUtils.createTeam(teamName);

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword(password)
                .setConfirmPassword(password)
                .clickAddNewUserBtn();

        TeamDetailPage teamDetailPage = userIndexPage
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickUserPermLink();

        assertTrue("A user with the correct permissions is not in the permissible user list.",
                teamDetailPage.isUserPresentPerm("user"));
        assertFalse("A user without the correct permissions is in the permissible user list.",
                teamDetailPage.isUserPresentPerm(userName));
    }

    @Test
    public void testTeamNotVisibleWithoutPermissions() {
        String roleName = getName();
        String user = getName();
        String hiddenTeam = getName();
        String hiddenApp = getName();

        initializeTeamAndApp();
        DatabaseUtils.createUser(user);
        DatabaseUtils.createTeam(hiddenTeam);
        DatabaseUtils.createApplication(hiddenTeam,hiddenApp);
        DatabaseUtils.createSpecificPermissionRole(roleName,"canGenerateReports");
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        loginPage.login(user, "TestPassword")
                .clickOrganizationHeaderLink();

        assertTrue("Hidden Team is present and shouldn't be",
                driver.findElements(By.id("teamName" + hiddenTeam)).isEmpty());
    }
}
