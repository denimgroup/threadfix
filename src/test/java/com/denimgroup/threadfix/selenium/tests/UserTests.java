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

import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;

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
		UserIndexPage userIndexPage = loginPage.login("user", "password")
												.clickManageUsersLink();

		assertFalse("User was already in the table.", userIndexPage.isUserNamePresent(userName));

		userIndexPage = userIndexPage.clickAddUserLink()
										.enterName(userName,null)
										.enterPassword(password,null)
										.enterConfirmPassword(password,null)
										.clickAddNewUserBtn();

		assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));
		userIndexPage = userIndexPage.clickDeleteButton(userName);
		assertFalse("User was still in table after attempted deletion.", userIndexPage.isUserNamePresent(userName));

		loginPage = userIndexPage.logout();
	}

	@Test 
	public void testUserFieldValidation() {

		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < 400; i++) { stringBuilder.append('i'); }

		String longInput = stringBuilder.toString();

		UserIndexPage userIndexPage = loginPage.login("user", "password")
											.clickManageUsersLink()
											.clickAddUserLink()
											.enterName("",null)
											.enterPassword("",null)
											.enterConfirmPassword("",null)
											.clickAddNewUserBtnInvalid();

		// Test Empty

		assertTrue("Name error not present", userIndexPage.getNameError().equals("Name is a required field."));
		assertTrue("Password error not present", userIndexPage.getPasswordError().equals("Password is a required field."));

		// Test White Space

		userIndexPage.enterName("        ",null);
		userIndexPage.enterPassword("  ",null);
		userIndexPage.enterConfirmPassword("  ",null);

		userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();

		assertTrue("Name error not present", userIndexPage.getNameError().equals("Name is a required field."));
		assertTrue("Password error not present", userIndexPage.getPasswordError().equals("Password is a required field."));

		// Test length
		userIndexPage.enterName("Test User",null);
		userIndexPage.enterPassword("test",null);
		userIndexPage.enterConfirmPassword("test",null);


		userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();

		assertTrue("Password length error not present", userIndexPage.getPasswordError().equals("Password has a minimum length of 12."));

		// Test non-matching passwords
		userIndexPage.enterName("new name",null);
		userIndexPage.enterPassword("lengthy password 1",null);
		userIndexPage.enterConfirmPassword("lengthy password 2",null);

		userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();
		assertTrue("Password matching error is not correct.", userIndexPage.getPasswordError().equals("Passwords do not match."));

		// Create a user
		userIndexPage.enterName(longInput,null);
		userIndexPage.enterPassword("dummy password",null);
		userIndexPage.enterConfirmPassword("dummy password",null);

		userIndexPage = userIndexPage.clickAddNewUserBtn();
		String userName = "iiiiiiiiiiiiiiiiiiiiiiiii";
		assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));


		userIndexPage = userIndexPage.clickAddUserLink();

		// Test name uniqueness check

		userIndexPage.enterName(userName,null);
		userIndexPage.enterPassword("dummy password",null);
		userIndexPage.enterConfirmPassword("dummy password",null);

		userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();
		assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));

		userIndexPage = userIndexPage.clickDeleteButton(userName);

		userIndexPage.logout();
	}

	@Test
	public void testEditUser() {
		String userName = "testCreateUser", password = "testCreateUser";
		String editedUserName = "testCreateUser3", editedPassword = "testCreateUser3";

		UserIndexPage userIndexPage = loginPage.login("user", "password")
											.clickManageUsersLink();

		assertFalse("User was already in the table.", userIndexPage.isUserNamePresent(userName));
		userIndexPage = userIndexPage.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword(password,null)
				.enterConfirmPassword(password,null)
				.clickAddNewUserBtn()
				.logout()
				.login(userName, password)
				.clickManageUsersLink()
				.clickEditLink(userName);
		
		userIndexPage.enterName(editedUserName,userName);
		userIndexPage.enterPassword(editedPassword,userName);
		userIndexPage.enterConfirmPassword(editedPassword,userName);
		

		// Save and check that the name changed

		userIndexPage = userIndexPage.clickUpdateUserBtn(userName);

		assertTrue("Username changed when edited.", userIndexPage.isUserNamePresent(editedUserName));

		// Test that we are able to log in the second time.
		// This ensures that the password was correctly updated.
		// if this messes up, the test won't complete.
		userIndexPage.logout().login(editedUserName, editedPassword)
							.clickManageUsersLink()
							.clickDeleteButtonSameUser(editedUserName);
	}

	@Test 
	public void testEditUserFieldValidation() {
		String baseUserName = "testEditUser";
		String userNameDuplicateTest = "duplicate user";

		// Set up the two User objects for the test

		UserIndexPage userIndexPage = loginPage.login("user", "password")
											.clickManageUsersLink()
											.clickAddUserLink()
											.enterName(baseUserName,null)
											.enterPassword("lengthy password 2",null)
											.enterConfirmPassword("lengthy password 2",null)
											.clickAddNewUserBtn()
											.clickAddUserLink()
											.enterName(userNameDuplicateTest,null)
											.enterPassword("lengthy password 2",null)
											.enterConfirmPassword("lengthy password 2",null)
											.clickAddNewUserBtn();



		// Test submission with no changes
		userIndexPage = userIndexPage.clickEditLink(baseUserName)
								.clickUpdateUserBtn(baseUserName);
		assertTrue("User name was not present in the table.",userIndexPage.isUserNamePresent(baseUserName));

		// Test Empty
		userIndexPage = userIndexPage.clickEditLink(baseUserName)
								.enterName("",baseUserName)
								.enterPassword("",baseUserName)
								.enterConfirmPassword("",baseUserName)
								.clickUpdateUserBtnInvalid(baseUserName);

		assertTrue("Name error not present", userIndexPage.getNameError().equals("Name is a required field."));
		//assertTrue("Password error not present", userIndexPage.getPasswordError().equals("Password is a required field."));

		// Test White Space
		userIndexPage = userIndexPage.enterName("        ",null)
								.enterPassword("  ",null)
								.enterConfirmPassword("  ",null)
								.clickUpdateUserBtnInvalid(baseUserName);



		assertTrue("Name error not present", userIndexPage.getNameError().equals("Name is a required field."));
		//assertTrue("Password error not present", userIndexPage.getPasswordError().equals("Password is a required field."));

		// Test non-matching passwords
		userIndexPage = userIndexPage.enterName("new name",null)
									.enterPassword("lengthy password 1",null)
									.enterConfirmPassword("lengthy password 2",null)
									.clickUpdateUserBtnInvalid(baseUserName);

		assertTrue("Password matching error is not correct.", userIndexPage.getPasswordError().equals("Passwords do not match."));

		// Test length
		userIndexPage = userIndexPage.enterName("Test User",null)
									.enterPassword("test",null)
									.enterConfirmPassword("test",null)
									.clickUpdateUserBtnInvalid(baseUserName);


		assertTrue("Password length error not present", userIndexPage.getPasswordError().equals("Password has a minimum length of 12."));

		// Test name uniqueness check
		userIndexPage = userIndexPage.enterName(userNameDuplicateTest,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickUpdateUserBtnInvalid(baseUserName);


		assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));

		// Delete the users and logout

		loginPage = userIndexPage.clickCancel()
				.clickDeleteButton(baseUserName)
				.clickDeleteButton(userNameDuplicateTest)
				.logout();
	}

	@Test
	public void navigationTest() {
		loginPage.login("user", "password")
				.clickManageUsersLink();

		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("User Password Change Page not found", PageText.contains("Manage Users"));
	}

	@Test
	public void testValidation() {
		changePasswordPage = loginPage.login("user", "password")
				.clickChangePasswordLink()
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
		UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName("testuser",null)
				.enterPassword("testpassword",null)
				.enterConfirmPassword("testpassword",null)
				.clickAddNewUserBtn()
				.logout()
				.login("testuser", "testpassword")
				.clickChangePasswordLink()
				.setConfirmPassword("newtestpassword")
				.setNewPassword("newtestpassword")
				.setCurrentPassword("testpassword")
				.clickUpdate()
				.logout()
				.login("testuser", "newtestpassword")
				.clickManageUsersLink()
				.clickDeleteButtonSameUser("testuser")
				.login("user", "password")
				.clickManageUsersLink();
	


		//assertFalse("Change password link present.", orgIndexPage.isElementPresent("changePasswordLink"));



		assertFalse("User was not deleted", userIndexPage.isUserNamePresent("testuser"));

		userIndexPage.logout();
	}
	
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
		
		userIndexPage.clickCancel();
	}
	
	
}
