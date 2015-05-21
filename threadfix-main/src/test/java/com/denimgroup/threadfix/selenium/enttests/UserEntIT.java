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
    public void testCreateUserWithoutGlobalAccess() {
        String userName = getName();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .createUser(userName,"",testPassword);
                //.clickEditLink(userName);

        assertFalse("Global Access was selected when it should not have been.",
                userIndexPage.getGlobalAccessRole() == "No Global Access");

        DashboardPage dashboardPage = userIndexPage.logout()
                .login(userName, testPassword);

        assertTrue("Alert was not shown on dashboard page.", dashboardPage.isPermissionsAlertDisplayed());
    }

    @Test
    public void testCreateUserWithGlobalAccess() {
        String userName = getName();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickCreateUserButton()
                .setName(userName)
                .setPassword(testPassword)
                .setConfirmPassword(testPassword)
                .clickAddNewUserBtn()
                .clickUserLink(userName)
                .chooseRoleForGlobalAccess("Administrator");

        DashboardPage dashboardPage = userIndexPage.clickAddNewUserBtn()
                .logout()
                .login(userName, testPassword);

        assertFalse("Alert was shown on dashboard page", dashboardPage.isPermissionsAlertDisplayed());
    }

	@Test
	public void testCreateLdapUser(){
		String userName = getName();

		UserIndexPage userIndexPage = loginPage.defaultLogin()
				.clickManageUsersLink()
                .clickCreateUserButton()
                .setName(userName)
				.toggleLDAP();
        assertFalse("Password fields are still present.", userIndexPage.isPasswordFieldEnabled());

        userIndexPage.clickAddNewUserBtn();
        assertTrue("LDAP user is not present in the user list.", userIndexPage.isUserNamePresent(userName));

	    userIndexPage.clickUserLink(userName);
		assertTrue("LDAP did not remain selected on creation.", userIndexPage.isLdapSelected());

		//turn ldap off
		userIndexPage = userIndexPage.toggleLDAP();
        assertTrue("Password fields are not present when switching from a LDAP user to regular user.",
                userIndexPage.isPasswordFieldEnabled());

        userIndexPage.setPassword(testPassword)
                .setConfirmPassword(testPassword)
                .clickUpdateUserBtn()
                .clickUserLink(userName);
		assertFalse("LDAP remained selected after editing.", userIndexPage.isLdapSelected());

		//turn ldap on
		userIndexPage = userIndexPage.toggleLDAP()
                .clickUpdateUserBtn()
                .clickUserLink(userName);
		assertTrue("LDAP did not remain selected after editing.", userIndexPage.isLdapSelected());
	}

	@Test
	public void testEditUserRole() {
        String userName = getName();

        UserIndexPage userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink()
                .clickCreateUserButton()
                .setName(userName)
                .setPassword(testPassword)
                .setConfirmPassword(testPassword)
                .clickAddNewUserBtn()
                .clickUserLink(userName)
                .chooseRoleForGlobalAccess("User")
                .clickSaveChanges();


        assertTrue("User role was not selected", userIndexPage.isRoleSelected(userName, "User"));

        // Change role to 'Read Access'
        userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Read Access")
                .clickUpdateUserBtn()
                .clickUserLink(userName);
        assertTrue("Read Access role was not selected", userIndexPage.isSuccessDisplayed("Edit succeeded."));
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
