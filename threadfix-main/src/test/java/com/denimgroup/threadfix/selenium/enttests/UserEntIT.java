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
import com.denimgroup.threadfix.selenium.pages.ConfigureDefaultsPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class UserEntIT extends BaseIT {

	//If this test fails it can cascade and cause several other tests to fail
    // TODO this test will not run correctly because of bugs involved with user creation
    @Ignore
	@Test
	public void testDeleteLastUserRemoveLastRole(){
        String newRole = "User";
		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickDeleteButton("user");
		assertTrue("User was deleted", userIndexPage.isUserNamePresent("user"));
		
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess(newRole, "user")
                .clickUpdateUserBtnInvalid("user");
		
		assertTrue("Global access removed.",userIndexPage.isGlobalAccessErrorPresent());
		
		userIndexPage.clickCancel("user");
	}

    //No Ldap users currently
    // TODO this test will not run correctly because of bugs involved with user creation
    @Ignore
	@Test
	public void createLdapUser(){
		String userName = "testLdapUser" + getRandomString(3);

		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword("TestPassword",null)
				.enterConfirmPassword("TestPassword",null)
				.clickLDAP(null)
				.clickAddNewUserBtn()
				.clickEditLink(userName);
		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(userName));

		//turn ldap off
		userIndexPage = userIndexPage.clickLDAP(userName)
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName);
		assertFalse("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(userName));

		//turn ldap on
		userIndexPage = userIndexPage.clickLDAP(userName)
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName)
                .clickCancel(userName);
		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(userName));
	}

    //No user roles currently
    // TODO this test will not run correctly because of bugs involved with editing user options
    @Ignore
	@Test
	public void editRoleTest(){
		String userName = "testChangeRoleUser" + getRandomString(3);

		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword("TestPassword", null)
				.enterConfirmPassword("TestPassword", null)
                .chooseRoleForGlobalAccess("Administrator", userName)
				.clickAddNewUserBtn()
				.clickEditLink(userName);
		assertTrue("User role was not selected",userIndexPage.isRoleSelected(userName, "User"));

        // Change role to 'Read Access'
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Read Access",userName)
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName);
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(userName, "Read Access"));

        // Revoke Global Access
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Administrator",userName)
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName)
				.clickGlobalAccess(userName)
				.clickUpdateUserBtn(userName)
				.clickEditLink(userName);
		assertFalse("Global Access was not revoked", userIndexPage.isGlobalAccessSelected(userName));

        // Reinstate Global Access
		userIndexPage = userIndexPage.clickGlobalAccess(userName)
                .clickUpdateUserBtn(userName)
                .clickEditLink(userName);
		assertTrue("Global Access was not Added", userIndexPage.isGlobalAccessSelected(userName));
	}

	// If this test fails with the defaults changed it could cause the other user tests to fail
	@Test
	public void defaultRoleTest(){
		String userName = "configureDefaultsUser" + getRandomString(3);

		ConfigureDefaultsPage configDefaultsPage = loginPage.login("user", "password")
                .clickConfigureDefaultsLink()
                .defaultPermissions()
                .checkGlobalGroupCheckbox()
                .setRoleSelect("User")
                .clickUpdateDefaults();
		assertTrue("Default changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		UserIndexPage userIndexPage = configDefaultsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName, null)
                .enterPassword("TestPassword", null)
                .enterConfirmPassword("TestPassword", null)
                .clickAddNewUserBtn()
                .clickEditLink(userName);
		assertTrue("User role was not selected",userIndexPage.isRoleSelected(userName, "User"));
		
		configDefaultsPage = userIndexPage.clickCancel(userName)
                .clickDelete(userName)
                .clickConfigureDefaultsLink()
                .defaultPermissions()
                .checkGlobalGroupCheckbox()
                .setRoleSelect("Administrator")
                .clickUpdateDefaults();
		assertTrue("Default changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		userIndexPage = configDefaultsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName, null)
                .enterPassword("TestPassword", null)
                .enterConfirmPassword("TestPassword", null)
                .clickAddNewUserBtn()
                .clickEditLink(userName);
		assertTrue("Administrator role was not selected",userIndexPage.isRoleSelected(userName, "Administrator"));
		
		configDefaultsPage = userIndexPage.clickCancel(userName)
                .clickDelete(userName)
                .clickConfigureDefaultsLink()
                .defaultPermissions()
                .checkGlobalGroupCheckbox()
                .setRoleSelect("Read Access")
                .clickUpdateDefaults();
		assertTrue("Default Changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		userIndexPage = configDefaultsPage.clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName,null)
                .enterPassword("TestPassword",null)
                .enterConfirmPassword("TestPassword",null)
                .clickAddNewUserBtn()
                .clickEditLink(userName);
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(userName, "Read Access"));
	}
}
