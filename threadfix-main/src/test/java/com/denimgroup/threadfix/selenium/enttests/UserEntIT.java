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
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.SystemSettingsPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class UserEntIT extends BaseIT {

    @Test
    public void createUserWithoutGlobalAccess() {
        String userName = getRandomString(8);
        String password = getRandomString(15);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .clickAddNewUserBtn()
                .clickEditLink(userName);

        assertFalse("Global Access was selected when it should not have been.", userIndexPage.isGlobalAccessSelected());

        DashboardPage dashboardPage = userIndexPage.logout()
                .login(userName, password);

        assertTrue("Alert was not shown on dashboard page.", dashboardPage.isAlertDisplayed());
    }

    @Test
    public void createUserWithGlobalAccess() {
        String userName = getRandomString(8);
        String password = getRandomString(15);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword(password)
                .enterConfirmPassword(password)
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess("Administrator")
                .clickAddNewUserBtn()
                .clickEditLink(userName);

        assertTrue("Global Access was not selected as it should have been.", userIndexPage.isGlobalAccessSelected());

        DashboardPage dashboardPage = userIndexPage.logout()
                .login(userName, password);

        assertFalse("Alert was shown on dashboard page", dashboardPage.isAlertDisplayed());
    }

    //TODO Fix this when LDAP user creation has changed.
    @Ignore
	@Test
	public void createLdapUser(){
		String userName = getRandomString(8);

		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword("TestPassword")
                .enterConfirmPassword("TestPassword")
				.toggleLDAP()
				.clickAddNewUserBtn()
				.clickEditLink(userName);

		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected());

		//turn ldap off
		userIndexPage = userIndexPage.toggleLDAP()
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName);
		assertFalse("LDAP remained selected on creation", userIndexPage.isLDAPSelected());

		//turn ldap on
		userIndexPage = userIndexPage.toggleLDAP()
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName)
                .clickCancel(userName);
		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected());
	}

	@Test
	public void editUserRoleTest(){
		String userName = getRandomString(8);

		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName)
				.enterPassword("TestPassword")
				.enterConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess("User")
				.clickAddNewUserBtn()
				.clickEditLink(userName);

		assertTrue("User role was not selected",userIndexPage.isRoleSelected(userName, "User"));

        // Change role to 'Read Access'
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Read Access")
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName);
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(userName, "Read Access"));

        // Revoke Global Access
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Administrator")
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName)
				.toggleGlobalAccess()
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName);
		assertFalse("Global Access was not revoked", userIndexPage.isGlobalAccessSelected());

        // Reinstate Global Access
		userIndexPage = userIndexPage.toggleGlobalAccess()
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName);
		assertTrue("Global Access was not Added", userIndexPage.isGlobalAccessSelected());
	}

    // TODO this is test is ignored because this feature seems to have changed to be LDAP specific
    @Ignore
	@Test
	public void defaultRoleTest(){
		String userName = "configureDefaultsUser" + getRandomString(3);

		SystemSettingsPage systemSettingsPage = loginPage.login("user", "password")
                .clickSystemSettingsLink()
                .defaultPermissions()
                .toggleDefaultRoleCheckbox()
                .setRole("User")
                .clickSaveChanges();

		assertTrue("Default permissions changes were not saved", systemSettingsPage.isSaveSuccessful());
		
		UserIndexPage userIndexPage = systemSettingsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword("TestPassword")
                .enterConfirmPassword("TestPassword")
                .clickAddNewUserBtn()
                .clickEditLink(userName);

		assertTrue("User role was not selected", userIndexPage.isRoleSelected(userName, "User"));
		
		systemSettingsPage = userIndexPage.clickCancel(userName)
                .clickDelete(userName)
                .clickSystemSettingsLink()
                .defaultPermissions()
                .toggleDefaultRoleCheckbox()
                .setRole("Administrator")
                .clickSaveChanges();

		assertTrue("Default changes not Saved",systemSettingsPage.isSaveSuccessful());
		
		userIndexPage = systemSettingsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword("TestPassword")
                .enterConfirmPassword("TestPassword")
                .clickAddNewUserBtn()
                .clickEditLink(userName);

		assertTrue("Administrator role was not selected", userIndexPage.isRoleSelected(userName, "Administrator"));
		
		systemSettingsPage = userIndexPage.clickCancel(userName)
                .clickDelete(userName)
                .clickSystemSettingsLink()
                .defaultPermissions()
                .toggleDefaultRoleCheckbox()
                .setRole("Read Access")
                .clickSaveChanges();

		assertTrue("Default Changes not Saved",systemSettingsPage.isSaveSuccessful());
		
		userIndexPage = systemSettingsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName)
                .enterPassword("TestPassword")
                .enterConfirmPassword("TestPassword")
                .clickAddNewUserBtn()
                .clickEditLink(userName);

		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(userName, "Read Access"));
	}

    //If this test fails it can cascade and cause several other tests to fail
    // TODO this test will not run correctly because of bugs involved with user creation
    @Ignore
    @Test
    public void testDeleteLastUserRemoveLastRole(){
        String newRole = getRandomString(8);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickDeleteButton("user");

        assertTrue("User was deleted", userIndexPage.isUserNamePresent("user"));

        userIndexPage = userIndexPage.chooseRoleForGlobalAccess(newRole, "user")
                .clickUpdateUserBtnInvalid("user");

        assertTrue("Global access removed.",userIndexPage.isGlobalAccessErrorPresent());

        userIndexPage.clickCancel("user");
    }

}
