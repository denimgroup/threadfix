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
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class ApplicationEnt extends BaseTest {

	private ApplicationDetailPage applicationDetailPage;

	@Test
	public void viewBasicPermissableUsers(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName)
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = applicationDetailPage.isUserPresentPerm("user");
		
		applicationDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.logout();
		assertTrue("user was not in the permissable user list",present);
	}

	@Test
	public void addAppOnlyUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String role = getRandomString(8);
		applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName)
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(role,null)
				.setPermissionValue("canManageApplications",true,null)
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
				.clickAllAppsNewPerm()
				.selectAppNewPerm(appName)
				.selectAppRoleNewPerm(appName, role)
				.clickAddMappingNewPerm()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = applicationDetailPage.isUserPresentPerm("user") && applicationDetailPage.isUserPresentPerm(userName);
		
		applicationDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.clickManageRolesLink()
								.clickDeleteButton(role)
								.clickManageUsersLink()
								.clickDeleteButton(userName)
								.logout();
		assertTrue("user was not in the permissable user list",present);
	}

	@Test
	public void addAppAllUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		String role = getRandomString(8);
		applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickAddNewApplication(teamName)
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName)
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(role,null)
				.setPermissionValue("canManageApplications",true,null)
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
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = applicationDetailPage.isUserPresentPerm("user") && applicationDetailPage.isUserPresentPerm(userName);
		
		applicationDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.clickManageRolesLink()
								.clickDeleteButton(role)
								.clickManageUsersLink()
								.clickDeleteButton(userName)
								.logout();
		assertTrue("user was not in the permissable user list",present);
	}

	@Test
	public void addUserNoPermUserView(){
		String teamName = getRandomString(8);
		String appName = getRandomString(8);
		String userName = getRandomString(8);
		String password = getRandomString(12);
		applicationDetailPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickAddTeamButton()
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName)
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword(password,null)
				.enterConfirmPassword(password,null)
				.clickGlobalAccess(null)
				.clickAddNewUserBtn()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickViewPermUsers();
		
//		int cnt = applicationDetailPage.getNumPermUsers();
		boolean present = applicationDetailPage.isUserPresentPerm("user") && !applicationDetailPage.isUserPresentPerm(userName);
		
		applicationDetailPage.clickOrganizationHeaderLink()
								.clickViewTeamLink(teamName)
								.clickDeleteButton()
								.clickManageUsersLink()
								.clickDeleteButton(userName)
								.logout();
		assertTrue("user was not in the permissable user list",present);	
	}
	
	public void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}
}
