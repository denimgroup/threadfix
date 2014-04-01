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

import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseTest;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class TeamEntTest extends BaseTest {

    // TODO test needs to be re-written as this functionality has moved
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

		assertTrue("user was not in the permissible user list",
                teamDetailPage.isUserPresentPerm("user") && teamDetailPage.isUserPresentPerm(userName));
	}

    //Ignore because this feature is not available in this version(2.0M2)
	@Test
	public void addAppAllUserView(){
		String teamName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String role = getRandomString(8);
        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(role,null)
				.setPermissionValue("canManageTeams",true,null)
				.clickSaveRole(null)
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword(password,null)
				.enterConfirmPassword(password,null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn()
				.clickEditPermissions(userName)
				.clickAddPermissionsLink()
				.setTeamNewPerm(teamName)
				.setRoleNewPerm(role)
				.clickAddMappingNewPerm()
				.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = teamDetailPage.isUserPresentPerm("user") && teamDetailPage.isUserPresentPerm(userName);
		
		teamDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.clickManageRolesLink()
								.clickDeleteButton(role)
								.clickManageUsersLink()
								.clickDeleteButton(userName)
								.logout();
		assertTrue("user was not in the permissable user list",present);
	}

    //Ignore because this feature is not available in this version(2.0M2)
	@Test
	public void addUserNoPermUserView(){
		String teamName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword(password,null)
				.enterConfirmPassword(password,null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn()
				.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickUserPermLink();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = teamDetailPage.isUserPresentPerm("user") && !teamDetailPage.isUserPresentPerm(userName);
		
		teamDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.clickManageUsersLink()
								.clickDeleteButton(userName)
								.logout();
		assertTrue("user was not in the permissable user list",present);	
	}
}
