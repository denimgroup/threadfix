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
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class TeamEntIT extends BaseDataTest {

    @Test
    public void testViewBasicPermissibleUsers(){
        String teamName = createTeam();
        String userName = createRegularUser();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
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
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();
        String hiddenTeam = createTeam();

        initializeTeamAndApp();
        DatabaseUtils.addUserWithTeamAppPermission(user,roleName,teamName,appName);

        loginPage.login(user, "TestPassword")
                .clickOrganizationHeaderLink();

        assertTrue("Hidden Team is present and shouldn't be",
                driver.findElements(By.id("teamName" + hiddenTeam)).isEmpty());
    }

    @Test
    public void testTeamIndexCountWithLimitedPermission() {
        String roleName = createSpecificPermissionRole("canGenerateReports");
        String user = createRegularUser();

        initializeTeamAndApp();
        String hiddenApp = createApplication(teamName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, hiddenApp, ScanContents.SCAN_FILE_MAP.get("WebInspect"));

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink();

        userIndexPage.clickUserLink(user)
                .clickAddApplicationRole()
                .setTeam(teamName)
                .setApplicationRole(appName,roleName)
                .clickSaveMap()
                .logout();

        TeamIndexPage teamIndexPage = loginPage.login(user, "TestPassword")
                .clickOrganizationHeaderLink();

        assertTrue("App vulnerabilities are shown which user should not have permissions to see.",
                teamIndexPage.teamVulnerabilitiesFiltered(teamName,"Total","44"));
    }

    @Test
    public void testDeleteTeamRestMethod(){
        String teamName = createTeam();

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();

        assertTrue("Team is not present", teamIndexPage.isTeamPresent(teamName));

        deleteTeam(teamName);

        teamIndexPage.refreshPage();

        assertFalse("Team is still present", teamIndexPage.isTeamPresent(teamName));
    }
}
