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
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class UserEntIT extends BaseDataTest {

    @Test
    public void createUserWithoutGlobalAccess() {
        String userName = getName();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .createUser(userName,"",testPassword)
                .clickEditLink(userName);

        assertFalse("Global Access was selected when it should not have been.", userIndexPage.isGlobalAccessSelected());

        DashboardPage dashboardPage = userIndexPage.logout()
                .login(userName, testPassword);

        assertTrue("Alert was not shown on dashboard page.", dashboardPage.isPermissionsAlertDisplayed());
    }

    @Test
    public void createUserWithGlobalAccess() {
        String userName = getName();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
                .setPassword(testPassword)
                .setConfirmPassword(testPassword)
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess("Administrator")
                .clickAddNewUserBtn()
                .clickEditLink(userName);

        assertTrue("Global Access was not selected as it should have been.", userIndexPage.isGlobalAccessSelected());

        DashboardPage dashboardPage = userIndexPage.clickAddNewUserBtn()
                .logout()
                .login(userName, testPassword);

        assertFalse("Alert was shown on dashboard page", dashboardPage.isPermissionsAlertDisplayed());
    }

	@Test
	public void createLdapUser(){
		String userName = getName();

		UserIndexPage userIndexPage = loginPage.defaultLogin()
				.clickManageUsersLink()
                .clickAddUserLink()
                .setName(userName)
				.toggleLDAP();
        assertFalse("Password fields are still present.", userIndexPage.isPasswordFieldPresent());

        userIndexPage.clickAddNewUserBtn();
        assertTrue("LDAP user is not present in the user list.", userIndexPage.isUserNamePresent(userName));

	    userIndexPage.clickEditLink(userName);
		assertTrue("LDAP did not remain selected on creation.", userIndexPage.isLDAPSelected());

		//turn ldap off
		userIndexPage = userIndexPage.toggleLDAP();
        assertTrue("Password fields are not present when switching from a LDAP user to regular user.",
                userIndexPage.isPasswordFieldPresent());

        userIndexPage.setPassword(testPassword)
                .setConfirmPassword(testPassword)
                .clickUpdateUserBtn()
                .clickEditLink(userName);
		assertFalse("LDAP remained selected after editing.", userIndexPage.isLDAPSelected());

		//turn ldap on
		userIndexPage = userIndexPage.toggleLDAP()
                .clickUpdateUserBtn()
                .clickEditLink(userName);
		assertTrue("LDAP did not remain selected after editing.", userIndexPage.isLDAPSelected());
	}

	@Test
	public void editUserRoleTest(){
		String userName = getName();

		UserIndexPage userIndexPage = loginPage.defaultLogin()
				.clickManageUsersLink()
				.clickAddUserLink()
				.setName(userName)
				.setPassword(testPassword)
				.setConfirmPassword(testPassword)
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess("User")
				.clickAddNewUserBtn()
				.clickEditLink(userName);



		assertTrue("User role was not selected",userIndexPage.isRoleSelected(userName, "User"));

        // Change role to 'Read Access'
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Read Access")
				.clickUpdateUserBtn()
				.clickEditLink(userName);
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(userName, "Read Access"));

        // Revoke Global Access
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Administrator")
				.clickUpdateUserBtn()
				.clickEditLink(userName)
				.toggleGlobalAccess()
				.clickUpdateUserBtn()
				.clickEditLink(userName);
		assertFalse("Global Access was not revoked", userIndexPage.isGlobalAccessSelected());

        // Reinstate Global Access
		userIndexPage = userIndexPage.toggleGlobalAccess()
                .clickUpdateUserBtn()
                .clickEditLink(userName);
		assertTrue("Global Access was not Added", userIndexPage.isGlobalAccessSelected());
	}

    //If this test fails it can cascade and cause several other tests to fail
    // TODO this test will not run correctly because of bugs involved with user creation
    /*@Test
      public void testDeleteLastUserRemoveLastRole(){
        String newRole = getRandomString(8);

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickDeleteButton("user");

        assertTrue("User was deleted", userIndexPage.isUserNamePresent("user"));

        userIndexPage = userIndexPage.chooseRoleForGlobalAccess(newRole)
                .clickUpdateUserBtnInvalid("user");

        assertTrue("Global access removed.",userIndexPage.isGlobalAccessErrorPresent());

        userIndexPage.clickCancel("user");
    }*/

}
