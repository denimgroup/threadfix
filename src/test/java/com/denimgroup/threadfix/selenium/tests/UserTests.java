////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.selenium.pages.ConfigurationIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserDetailPage;
import com.denimgroup.threadfix.selenium.pages.UserEditPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserNewPage;

public class UserTests extends BaseTest {

	private WebDriver driver;
	private static LoginPage loginPage;
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test
	public void testCreateUser() {
		String userName = "testCreateUser", password = "testCreateUser";
		
		OrganizationIndexPage organizationIndexPage = loginPage.login("user", "password");
		ConfigurationIndexPage configurationIndexPage = organizationIndexPage.clickConfigurationHeaderLink();

		UserIndexPage userIndexPage = configurationIndexPage.clickManageUsersLink();
		assertFalse("User was already in the table.", userIndexPage.isUserNamePresent(userName));
		
		UserNewPage newUserPage = userIndexPage.clickAddUserLink();
		
		newUserPage.setNameInput(userName);
		newUserPage.setPasswordInput(userName);
		newUserPage.setPasswordConfirmInput(password);
		newUserPage.setRoleSelect("Administrator");
				
		UserDetailPage userDetailPage = newUserPage.clickAddUserButton();
		assertTrue("User name was not preserved correctly.", userDetailPage.getNameText().equals(userName));
		
		userIndexPage = userDetailPage.clickBackToListLink();
		assertTrue("User was not in table.", userIndexPage.isUserNamePresent(userName));
		
		userDetailPage = userIndexPage.clickUserNameLink(userName);
		userIndexPage = userDetailPage.clickDeleteLink();
		
		assertFalse("User was still in table after attempted deletion.", userIndexPage.isUserNamePresent(userName));
	
		loginPage = userIndexPage.logout();
	}
	
	@Test 
	public void testUserFieldValidation() {

		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < 400; i++) { stringBuilder.append('i'); }
		
		String longInput = stringBuilder.toString();
		
		OrganizationIndexPage organizationIndexPage = loginPage.login("user", "password");
		ConfigurationIndexPage configurationIndexPage = organizationIndexPage.clickConfigurationHeaderLink();

		UserIndexPage userIndexPage = configurationIndexPage.clickManageUsersLink();
		
		UserNewPage newUserPage = userIndexPage.clickAddUserLink();
		
		// Test Empty
		newUserPage = newUserPage.clickAddUserButtonInvalid();
		
		assertTrue("Name error not present", newUserPage.getNameError().equals("Name is a required field."));
		assertTrue("Role error not present", newUserPage.getRoleError().equals("Role is a required field."));
		assertTrue("Password error not present", newUserPage.getPasswordError().equals("Password is a required field."));
		
		// Test White Space
		
		newUserPage.setNameInput("        ");
		newUserPage.setPasswordInput("  ");
		newUserPage.setPasswordConfirmInput("  ");
		
		newUserPage = newUserPage.clickAddUserButtonInvalid();
		
		assertTrue("Name error not present", newUserPage.getNameError().equals("Name is a required field."));
		assertTrue("Role error not present", newUserPage.getRoleError().equals("Role is a required field."));
		assertTrue("Password error not present", newUserPage.getPasswordError().equals("Password is a required field."));
		
		// Test non-matching passwords
		newUserPage.setNameInput("new name");
		newUserPage.setPasswordInput("password 1");
		newUserPage.setPasswordConfirmInput("password 2");
		newUserPage.setRoleSelect("Administrator");
		
		newUserPage = newUserPage.clickAddUserButtonInvalid();
		assertTrue("Password matching error is not correct.", newUserPage.getPasswordError().equals("Passwords do not match."));
		
		// Create a user
		newUserPage.setNameInput(longInput);
		newUserPage.setPasswordInput(longInput);
		newUserPage.setPasswordConfirmInput(longInput);
		newUserPage.setRoleSelect("Administrator");
				
		UserDetailPage userDetailPage = newUserPage.clickAddUserButton();
		assertTrue("User name limit was not correct", userDetailPage.getNameText().length() == User.NAME_LENGTH);
		
		String userName = userDetailPage.getNameText();
		
		newUserPage = userDetailPage.clickBackToListLink().clickAddUserLink();
		
		// Test name uniqueness check
		
		newUserPage.setNameInput(userName);
		newUserPage.setRoleSelect("Administrator");
		newUserPage.setPasswordConfirmInput("1");
		newUserPage.setPasswordInput("1");
		
		newUserPage = newUserPage.clickAddUserButtonInvalid();
		assertTrue("Name uniqueness error is not correct.", newUserPage.getNameError().equals("That name is already taken."));
		
		userIndexPage = newUserPage.clickCancelLink().clickUserNameLink(userName).clickDeleteLink();
		
		userIndexPage.logout();
	}
	
	@Test
	public void testEditUser() {
		String userName = "testCreateUser", password = "testCreateUser";
		String editedUserName = "testCreateUser3", editedPassword = "testCreateUser3";
		
		UserNewPage newUserPage = loginPage.login("user", "password")
											.clickConfigurationHeaderLink()
											.clickManageUsersLink()
											.clickAddUserLink();
				
		newUserPage.setNameInput(userName);
		newUserPage.setPasswordInput(userName);
		newUserPage.setPasswordConfirmInput(password);
		newUserPage.setRoleSelect("Administrator");
				
		UserEditPage editUserPage = newUserPage.clickAddUserButton()
											    .logout()
											    .login(userName, password)
											    .clickConfigurationHeaderLink()
											    .clickManageUsersLink()
											    .clickUserNameLink(userName)
											    .clickEditLink();

		editUserPage.setNameInput(editedUserName);
		editUserPage.setPasswordConfirmInput(editedPassword);
		editUserPage.setPasswordInput(editedPassword);
		
		// Save and check that the name changed
		
		UserDetailPage userDetailPage = editUserPage.clickUpdateUserButton();
		
		assertTrue("Username changed when edited.", userDetailPage.getNameText().equals(editedUserName));
		
		// Test that we are able to log in the second time.
		// This ensures that the password was correctly updated.
		// if this messes up, the test won't complete.
		
		loginPage = userDetailPage.logout()
								    .login(editedUserName, editedPassword)
								    .clickConfigurationHeaderLink()
								    .clickManageUsersLink()
								    .clickUserNameLink(userName)
								    .clickDeleteLink()
								    .logout();
	}
	
	@Test 
	public void testEditUserFieldValidation() {
		String baseUserName = "testEditUser";
		String userNameDuplicateTest = "duplicate user";
		
		// Set up the two User objects for the test
		
		UserNewPage newUserPage = loginPage.login("user", "password")
											.clickConfigurationHeaderLink()
											.clickManageUsersLink()
											.clickAddUserLink();

		newUserPage.setNameInput(userNameDuplicateTest);
		newUserPage.setPasswordInput(userNameDuplicateTest);
		newUserPage.setPasswordConfirmInput(userNameDuplicateTest);
		newUserPage.setRoleSelect("Administrator");

		newUserPage = newUserPage.clickAddUserButton().clickBackToListLink().clickAddUserLink();
		
		newUserPage.setNameInput(baseUserName);
		newUserPage.setPasswordInput(baseUserName);
		newUserPage.setPasswordConfirmInput(baseUserName);
		newUserPage.setRoleSelect("Administrator");
		
		// Test submission with no changes
		UserDetailPage userDetailPage = newUserPage.clickAddUserButton().clickEditLink().clickUpdateUserButton();
		assertTrue("User name was not preserved correctly.", userDetailPage.getNameText().equals(baseUserName));
		UserEditPage editUserPage = userDetailPage.clickEditLink();
		
		// Test Empty
		editUserPage.setNameInput("");
		editUserPage.setPasswordInput("");
		editUserPage.setPasswordConfirmInput("");
		
		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		
		assertTrue("Name error not present", editUserPage.getNameError().equals("Name is a required field."));

		// Test White Space
		editUserPage.setNameInput("        ");
		editUserPage.setPasswordInput("  ");
		editUserPage.setPasswordConfirmInput("  ");
		
		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		
		assertTrue("Name error not present", editUserPage.getNameError().equals("Name is a required field."));

		// Test non-matching passwords
		editUserPage.setNameInput("new name");
		editUserPage.setPasswordInput("password 1");
		editUserPage.setPasswordConfirmInput("password 2");
		editUserPage.setRoleSelect("Administrator");
		
		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		assertTrue("Password matching error is not correct.", editUserPage.getPasswordError().equals("Passwords do not match."));
		
		// Test name uniqueness check
		
		editUserPage.setNameInput(userNameDuplicateTest);
		editUserPage.setRoleSelect("Administrator");
		editUserPage.setPasswordConfirmInput("1");
		editUserPage.setPasswordInput("1");
		
		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		assertTrue("Name uniqueness error is not correct.", editUserPage.getNameError().equals("That name is already taken."));
		
		// Delete the users and logout
		
		loginPage = editUserPage.clickCancelLink()
								.clickUserNameLink(baseUserName)
								.clickDeleteLink()
								.clickUserNameLink(userNameDuplicateTest)
								.clickDeleteLink()
								.logout();
	}
	
}
