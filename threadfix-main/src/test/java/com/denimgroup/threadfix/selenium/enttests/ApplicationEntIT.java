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

import com.denimgroup.threadfix.selenium.RegressionTest;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserPermissionsPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(RegressionTest.EnterpriseTest.class)
public class ApplicationEntIT extends BaseIT {

    // Todo, functionality that this test is looking for is not present
    @Ignore
	@Test
	public void viewBasicPermissibleUsers(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

		ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
		assertTrue("user was not in the permissible user list", applicationDetailPage.isUserPresentPerm("user"));
	}

    // Todo, functionality that this test is looking for is not present
    @Ignore
	@Test
	public void addAppOnlyUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String role = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(role, null)
				.setPermissionValue("canManageApplications", true, null)
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
				.clickAllAppsNewPerm()
				.selectAppNewPerm(appName)
				.selectAppRoleNewPerm(appName, role)
				.clickAddMappingNewPerm();

        ApplicationDetailPage applicationDetailPage = userPermissionsPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
		assertTrue("The user was not in the permissible user list",
                applicationDetailPage.isUserPresentPerm("user") && applicationDetailPage.isUserPresentPerm(userName));
	}

    // Todo, functionality that this test is looking for is not present
    @Ignore
	@Test
	public void addAppAllUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String role = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(role, null)
				.setPermissionValue("canManageApplications", true, null)
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
				.setRoleNewPerm(role)
				.clickAddMappingNewPerm();

        ApplicationDetailPage applicationDetailPage = userPermissionsPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
		assertTrue("user was not in the permissible user list",
                applicationDetailPage.isUserPresentPerm("user") && applicationDetailPage.isUserPresentPerm(userName));
	}

    // Todo, functionality that this test is looking for is not present
    @Ignore
	@Test
	public void addUserNoPermUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword(password, null)
				.enterConfirmPassword(password, null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn();

        ApplicationDetailPage applicationDetailPage = userIndexPage.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
		assertTrue("user was not in the permissible user list",
                applicationDetailPage.isUserPresentPerm("user") && !applicationDetailPage.isUserPresentPerm(userName));
	}
}
