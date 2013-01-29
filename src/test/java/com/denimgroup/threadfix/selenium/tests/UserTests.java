////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.ConfigurationIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.OrganizationIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserEditPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserNewPage;

public class UserTests extends BaseTest {

	private RemoteWebDriver driver;
	private UserChangePasswordPage changePasswordPage;
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

		userIndexPage = newUserPage.clickAddUserButton().clickCancelLink();
		assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));

		userIndexPage = userIndexPage.clickDeleteButton(userName);
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
		assertTrue("Password error not present", newUserPage.getPasswordError().equals("Password is a required field."));

		// Test White Space

		newUserPage.setNameInput("        ");
		newUserPage.setPasswordInput("  ");
		newUserPage.setPasswordConfirmInput("  ");

		newUserPage = newUserPage.clickAddUserButtonInvalid();

		assertTrue("Name error not present", newUserPage.getNameError().equals("Name is a required field."));
		assertTrue("Password error not present", newUserPage.getPasswordError().equals("Password is a required field."));

		// Test length
		newUserPage.setNameInput("Test User");
		newUserPage.setPasswordInput("test");
		newUserPage.setPasswordConfirmInput("test");

		newUserPage = newUserPage.clickAddUserButtonInvalid();

		assertTrue("Password length error not present", newUserPage.getPasswordError().equals("Password has a minimum length of 12."));

		// Test non-matching passwords
		newUserPage.setNameInput("new name");
		newUserPage.setPasswordInput("lengthy password 1");
		newUserPage.setPasswordConfirmInput("lengthy password 2");

		newUserPage = newUserPage.clickAddUserButtonInvalid();
		assertTrue("Password matching error is not correct.", newUserPage.getPasswordError().equals("Passwords do not match."));

		// Create a user
		newUserPage.setNameInput(longInput);
		newUserPage.setPasswordInput("dummy password");
		newUserPage.setPasswordConfirmInput("dummy password");

		userIndexPage = newUserPage.clickAddUserButton().clickCancelLink();

		String userName = "iiiiiiiiiiiiiiiiiiiiiiiii";

		newUserPage = userIndexPage.clickAddUserLink();

		// Test name uniqueness check

		newUserPage.setNameInput(userName);
		newUserPage.setPasswordConfirmInput("dummy password");
		newUserPage.setPasswordInput("dummy password");

		newUserPage = newUserPage.clickAddUserButtonInvalid();
		assertTrue("Name uniqueness error is not correct.", newUserPage.getNameError().equals("That name is already taken."));

		userIndexPage = newUserPage.clickCancelLink().clickDeleteButton(userName);

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

		UserEditPage editUserPage = newUserPage.clickAddUserButton()
				.logout()
				.login(userName, password)
				.clickConfigurationHeaderLink()
				.clickManageUsersLink()
				.clickEditLink(userName);

		editUserPage.setNameInput(editedUserName);
		editUserPage.setPasswordConfirmInput(editedPassword);
		editUserPage.setPasswordInput(editedPassword);

		// Save and check that the name changed

		UserIndexPage userIndexPage = editUserPage.clickUpdateUserButton();

		assertTrue("Username changed when edited.", userIndexPage.isUserNamePresent(editedUserName));

		// Test that we are able to log in the second time.
		// This ensures that the password was correctly updated.
		// if this messes up, the test won't complete.
		userIndexPage.logout().login(editedUserName, editedPassword)
		.clickConfigurationHeaderLink()
		.clickManageUsersLink()
		.clickDeleteButtonSameUser(editedUserName);
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

		newUserPage = newUserPage.clickAddUserButton().clickCancelLink()
				.clickAddUserLink();

		newUserPage.setNameInput(baseUserName);
		newUserPage.setPasswordInput(baseUserName);
		newUserPage.setPasswordConfirmInput(baseUserName);

		// Test submission with no changes
		UserIndexPage userIndexPage = newUserPage
				.clickAddUserButton()
				.clickUpdateUserButton();
		assertTrue("User name was not present in the table.",userIndexPage.isUserNamePresent(baseUserName));
		UserEditPage editUserPage = userIndexPage.clickEditLink(baseUserName);

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
		editUserPage.setPasswordInput("lengthy password 1");
		editUserPage.setPasswordConfirmInput("lengthy password 2");
		editUserPage.setRoleSelect("Administrator");

		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		assertTrue("Password matching error is not correct.", editUserPage.getPasswordError().equals("Passwords do not match."));

		// Test length
		editUserPage.setNameInput("Test User");
		editUserPage.setPasswordInput("test");
		editUserPage.setPasswordConfirmInput("test");

		editUserPage = editUserPage.clickUpdateUserButtonInvalid();

		assertTrue("Password length error not present", editUserPage.getPasswordError().equals("Password has a minimum length of 12."));

		// Test name uniqueness check

		editUserPage.setNameInput(userNameDuplicateTest);
		editUserPage.setRoleSelect("Administrator");
		editUserPage.setPasswordConfirmInput("lengthy password 2");
		editUserPage.setPasswordInput("lengthy password 2");

		editUserPage = editUserPage.clickUpdateUserButtonInvalid();
		assertTrue("Name uniqueness error is not correct.", editUserPage.getNameError().equals("That name is already taken."));

		// Delete the users and logout

		loginPage = editUserPage.clickCancelLink()
				.clickDeleteButton(baseUserName)
				.clickDeleteButton(userNameDuplicateTest)
				.logout();
	}

	@Test
	public void navigationTest() {
		loginPage.login("user", "password")
		.clickConfigurationHeaderLink()
		.clickChangeMyPasswordLink();

		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("User Password Change Page not found", PageText.contains("User Password Change"));
	}

	@Test
	public void testValidation() {
		changePasswordPage = loginPage.login("user", "password")
				.clickConfigurationHeaderLink()
				.clickChangeMyPasswordLink()
				.setCurrentPassword(" ")
				.setNewPassword("password1234")
				.setConfirmPassword("password1234")
				.clickUpdateInvalid();

		assertTrue("Incorrect password error not present",
				changePasswordPage.getErrorText("currentPassword")
				.contains("That was not the correct password."));

		// New Pwd
		changePasswordPage = changePasswordPage.setCurrentPassword("password")
				.setNewPassword("                     ")
				.setConfirmPassword("password1234")
				.clickUpdateInvalid();

		assertTrue("Password match error not present",
				changePasswordPage.getErrorText("password")
				.contains("Passwords do not match."));

		// Confirm Pwd
		changePasswordPage = changePasswordPage.setCurrentPassword("password")
				.setConfirmPassword("                  ")
				.setNewPassword("password1234")
				.clickUpdateInvalid();

		assertTrue("Password match error not present",
				changePasswordPage.getErrorText("password")
				.contains("Passwords do not match."));

		// PwdLength
		changePasswordPage = changePasswordPage.setCurrentPassword("password")
				.setConfirmPassword("      ")
				.setNewPassword("password124")
				.clickUpdateInvalid();

		assertTrue("Length error missing",
				changePasswordPage.getErrorText("password")
				.contains("Password has a minimum length of 12."));

		changePasswordPage.logout();
	}

	@Test
	public void testChangePassword() {
		OrganizationIndexPage orgIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickManageUsersLink()
				.clickAddUserLink()
				.setNameInput("testuser")
				.setPasswordConfirmInput("testpassword")
				.setPasswordInput("testpassword")
				.clickAddUserButton()
				.logout()
				.login("testuser", "testpassword");

		assertTrue("Change password link not present.", orgIndexPage.isElementPresent("changePasswordLink"));		

		orgIndexPage = orgIndexPage.clickChangePasswordLinkIfPresent()
				.setConfirmPassword("newtestpassword")
				.setNewPassword("newtestpassword")
				.setCurrentPassword("testpassword")
				.clickUpdate()
				.logout()
				.login("testuser", "newtestpassword");

		assertFalse("Change password link present.", orgIndexPage.isElementPresent("changePasswordLink"));

		UserIndexPage userIndexPage = orgIndexPage.clickConfigurationHeaderLink()
				.clickManageUsersLink()
				.clickDeleteButtonSameUser("testuser")
				.login("user", "password")
				.clickConfigurationHeaderLink()
				.clickManageUsersLink();

		assertFalse("User was not deleted", userIndexPage.isUserNamePresent("testuser"));

		userIndexPage.logout();
	}
}
