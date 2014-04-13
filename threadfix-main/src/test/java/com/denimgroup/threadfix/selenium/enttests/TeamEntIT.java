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

import com.denimgroup.threadfix.selenium.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserPermissionsPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class TeamEntIT extends BaseIT {

    // TODO this element does not exist in the build currently
    @Ignore
    @Test
    public void teamPermissibleUsersModalTest(){
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickUserPermLink();

        assertTrue("Edit Perm link was not present", teamDetailPage.isPUEditPermLinkPresent());
        assertTrue("Edit Perm link was not clickable", teamDetailPage.isPUEditPermLinkClickable());
        assertTrue("Close button was not present", teamDetailPage.isPUClosePresent());
        assertTrue("Close button was not clickable", teamDetailPage.isPUCloseClickable());
    }

    // TODO test needs to be re-written as this functionality has moved or is not being created properly
    @Ignore
	@Test
	public void viewBasicPermissibleUsers(){
		String teamName = getRandomString(8);
        DatabaseUtils.createTeam(teamName);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();

        assertTrue("The user was not in the permissible user list", teamDetailPage.isUserPresentPerm("user"));
	}

    // TODO test needs to be re-written as this functionality has moved or is not being created properly
    @Ignore
	@Test
	public void addAppOnlyUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
        String userName = getRandomString(8);
        String newPassword = getRandomString(12);
        String newRole = "newRole" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(newRole,null)
				.setPermissionValue("canManageTeams",true,null)
				.clickSaveRole(null);

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword(newPassword, null)
				.enterConfirmPassword(newPassword, null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
				.clickAddPermissionsLink()
				.setTeamNewPerm(teamName)
				.clickAllAppsNewPerm()
				.selectAppNewPerm(appName)
				.selectAppRoleNewPerm(appName, newRole)
				.clickAddMappingNewPerm();

        TeamDetailPage teamDetailPage = userPermissionsPage.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();

		assertTrue("The user was not in the permissible user list",
                teamDetailPage.isUserPresentPerm("user") && teamDetailPage.isUserPresentPerm(userName));
	}

    // TODO test needs to be re-written as this functionality has moved or is not being created properly
    @Ignore
	@Test
	public void addAppAllUserView(){
		String teamName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String newRole = "newRole" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(newRole, null)
				.setPermissionValue("canManageTeams", true, null)
				.clickSaveRole(null);

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword(password, null)
				.enterConfirmPassword(password, null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn();

        UserPermissionsPage userPermissionsPage = userIndexPage.clickEditPermissions(userName)
				.clickAddPermissionsLink()
				.setTeamNewPerm(teamName)
				.setRoleNewPerm(newRole)
				.clickAddMappingNewPerm();

        TeamDetailPage teamDetailPage = userPermissionsPage.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();
		
		assertTrue("The user was not in the permissible user list",
                teamDetailPage.isUserPresentPerm("user") && teamDetailPage.isUserPresentPerm(userName));
	}

    // TODO test needs to be re-written as this functionality has moved or is not being created properly
    @Ignore
	@Test
	public void addUserNoPermUserView(){
		String teamName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);

        DatabaseUtils.createTeam(teamName);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword(password, null)
				.enterConfirmPassword(password, null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn();

        TeamDetailPage teamDetailPage = userIndexPage.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();

		assertTrue("The user was not in the permissible user list",
                teamDetailPage.isUserPresentPerm("user") && !teamDetailPage.isUserPresentPerm(userName));
	}
}
