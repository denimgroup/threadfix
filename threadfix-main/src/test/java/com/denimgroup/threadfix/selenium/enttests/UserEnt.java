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
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UserEnt extends BaseTest {

	//If this test fails it can cascade and cause several other tests to fail
	@Test
	public void testDeleteLastUserRemoveLastRole(){
		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickDeleteButton("user");
		assertTrue("User was deleted", userIndexPage.isUserNamePresent("user"));
		
		userIndexPage = userIndexPage.clickEditLink("user")
									.chooseRoleForGlobalAccess("User", "user")
									.clickUpdateUserBtnInvalid("user");
		
		assertTrue("Global access removed.",userIndexPage.isGlobalAccessErrorPresent());
		
		userIndexPage.clickCancel("user");
	}

    //No Ldap users currently
	@Test
	public void createLdapUser(){
		String baseUserName = "testLdapUser";
		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(baseUserName,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickLDAP(null)
				.clickAddNewUserBtn()
				.clickEditLink(baseUserName);
		
		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(baseUserName));
		//turnoff ldap
		userIndexPage = userIndexPage.clickLDAP(baseUserName)
									.clickUpdateUserBtn(baseUserName)
									.clickEditLink(baseUserName);
		
		assertFalse("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(baseUserName));
		//turn ldap on
		userIndexPage = userIndexPage.clickLDAP(baseUserName)
									.clickUpdateUserBtn(baseUserName)
									.clickEditLink(baseUserName)
									.clickCancel(baseUserName);
		
		assertTrue("LDAP did not remain selected on creation", userIndexPage.isLDAPSelected(baseUserName));
		
		userIndexPage.clickDeleteButton(baseUserName)
					.logout();
		
		
	}

    //No user roles currently
	@Test
	public void changeUserRoleTest(){
		String baseUserName = "testChangeRoleUser";
		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(baseUserName,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickAddNewUserBtn()
				.clickEditLink(baseUserName);
		
		assertTrue("Administrator role was not selected",userIndexPage.isRoleSelected(baseUserName, "Administrator"));
		
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("User",baseUserName)
									.clickUpdateUserBtn(baseUserName)
									.clickEditLink(baseUserName);
		
		assertTrue("User role was not selected", userIndexPage.isRoleSelected(baseUserName, "User"));
		
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Read Access",baseUserName)
				.clickUpdateUserBtn(baseUserName)
				.clickEditLink(baseUserName);
		
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(baseUserName, "Read Access"));
		
		userIndexPage = userIndexPage.chooseRoleForGlobalAccess("Administrator",baseUserName)
				.clickUpdateUserBtn(baseUserName)
				.clickEditLink(baseUserName)
				.clickGlobalAccess(baseUserName)
				.clickUpdateUserBtn(baseUserName)
				.clickEditLink(baseUserName);
		
		assertFalse("Global Access was not revoked", userIndexPage.isGlobalAccessSelected(baseUserName));
		
		userIndexPage = userIndexPage.clickGlobalAccess(baseUserName)
									.clickUpdateUserBtn(baseUserName)
									.clickEditLink(baseUserName);

		assertTrue("Global Access was not Added", userIndexPage.isGlobalAccessSelected(baseUserName));
		
		userIndexPage.clickCancel(baseUserName)
					.clickDeleteButton(baseUserName)
					.logout();
		
		
	}

	// If this test fails with the defaults changed it could cause the other user tests to fail
	@Test
	public void disableGlobalAccessTest(){
		String baseUserName = "configureDefaultsUser";
		ConfigureDefaultsPage configDefaultsPage = loginPage.login("user", "password")
											.clickConfigureDefaultsLink()
											.setRoleSelect("User")
											.clickUpdateDefaults();
		
		assertTrue("Default Changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		UserIndexPage userIndexPage = configDefaultsPage.clickManageUsersLink()
														.clickAddUserLink()
														.enterName(baseUserName,null)
														.enterPassword("lengthy password 2",null)
														.enterConfirmPassword("lengthy password 2",null)
														.clickAddNewUserBtn()
														.clickEditLink(baseUserName);
		
		assertTrue("User role was not selected",userIndexPage.isRoleSelected(baseUserName, "User"));
		
		configDefaultsPage = userIndexPage.clickCancel(baseUserName)
										.clickDeleteButton(baseUserName)
										.clickConfigureDefaultsLink()
										.setRoleSelect("Administrator")
										.clickUpdateDefaults();
		
		assertTrue("Default Changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		userIndexPage = configDefaultsPage.clickManageUsersLink()
										.clickAddUserLink()
										.enterName(baseUserName,null)
										.enterPassword("lengthy password 2",null)
										.enterConfirmPassword("lengthy password 2",null)
										.clickAddNewUserBtn()
										.clickEditLink(baseUserName);
		
		assertTrue("Administrator role was not selected",userIndexPage.isRoleSelected(baseUserName, "Administrator"));
		
		configDefaultsPage = userIndexPage.clickCancel(baseUserName)
										.clickDeleteButton(baseUserName)
										.clickConfigureDefaultsLink()
										.checkGlobalGroupCheckbox()
										.clickUpdateDefaults();
		
		assertTrue("Default Changes not Saved",configDefaultsPage.isSaveSuccessful());
		
		userIndexPage = configDefaultsPage.clickManageUsersLink()
										.clickAddUserLink()
										.enterName(baseUserName,null)
										.enterPassword("lengthy password 2",null)
										.enterConfirmPassword("lengthy password 2",null)
										.clickAddNewUserBtn()
										.clickEditLink(baseUserName);
		
		assertTrue("Read Access role was not selected",userIndexPage.isRoleSelected(baseUserName, "Read Access"));
		
		userIndexPage.clickCancel(baseUserName)
					.clickDeleteButton(baseUserName)
					.clickConfigureDefaultsLink()
					.checkGlobalGroupCheckbox()
					.clickUpdateDefaults()
					.logout();
			
	}
}
