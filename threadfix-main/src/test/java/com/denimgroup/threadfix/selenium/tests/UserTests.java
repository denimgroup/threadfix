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
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.ConfigureDefaultsPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;

public class UserTests extends BaseTest {

	public UserTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private RemoteWebDriver driver;
	private UserChangePasswordPage changePasswordPage;
	private static LoginPage loginPage;

	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
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
		DashboardPage dashboardPage;
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
		userIndexPage.enterPassword(longInput,null);
		userIndexPage.enterConfirmPassword(longInput,null);

		userIndexPage = userIndexPage.clickAddNewUserBtn();
		
		String userName = "iiiiiiiiiiiiiiiiiiiiiiiii";
		assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));
		
		dashboardPage = userIndexPage.logout()
					.login(userName, longInput);
		
		assertTrue("user: "+longInput+" was not logged in.",dashboardPage.isLoggedInUser(userName));
		
		userIndexPage = dashboardPage.logout()
					.login("user", "password")
					.clickManageUsersLink()
					.clickAddUserLink();
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
		DashboardPage dashboardPage;
		String baseUserName = "testEditUser";
		String userNameDuplicateTest = "duplicate user";
		StringBuilder stringBuilder = new StringBuilder("");
		for (int i = 0; i < 400; i++) { stringBuilder.append('a'); }

		String longInput = stringBuilder.toString();

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
		userIndexPage = userIndexPage.clickManageUsersLink()
								.clickEditLink(baseUserName)
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


		assertTrue("Password length error not present", userIndexPage.getPasswordError().contains("Password has a minimum length of 12."));
		
		//max length check
		userIndexPage = userIndexPage.enterName(longInput,null)
				.enterPassword(longInput,null)
				.enterConfirmPassword(longInput,null)
				.clickUpdateUserBtn(baseUserName);
						  
		String userName = "aaaaaaaaaaaaaaaaaaaaaaaaa";
		assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));
		dashboardPage = userIndexPage.logout()
				.login(userName, longInput);
	
		assertTrue("user: "+longInput+" was not logged in.",dashboardPage.isLoggedInUser(userName));
	
		// Test name uniqueness check
		userIndexPage = dashboardPage.logout()
				.login("user", "password")
				.clickManageUsersLink()
				.clickEditLink(userName)
				.enterName(userNameDuplicateTest,userName)
				.enterPassword("lengthy password 2",userName)
				.enterConfirmPassword("lengthy password 2",userName)
				.clickUpdateUserBtnInvalid(userName);


		assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));

		// Delete the users and logout

		userIndexPage = userIndexPage.clickCancel(userName)
				.clickManageUsersLink()
				.clickDeleteButton(userName)
				.clickDeleteButton(userNameDuplicateTest);
		
		assertFalse("User was still in table after attempted deletion.", userIndexPage.isUserNamePresent(baseUserName));
		assertFalse("User was still in table after attempted deletion.", userIndexPage.isUserNamePresent(userNameDuplicateTest));
		
		
	}

	@Test
	public void navigationTest() {
		loginPage.login("user", "password")
				.clickManageUsersLink();

		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("User Password Change Page not found", PageText.contains("Manage Users"));
	}

	@Test
	public void testChangePasswordValidation() {
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
	//If this test fails it can cascade and cause several other tests to fail
	@Ignore
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
		
		assertTrue("User role was not selected",userIndexPage.isRoleSelected(baseUserName, "User"));
		
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
	@Ignore
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
	
	@Test
	public void userPasswordChangeTest(){
		String baseUserName = "passwordChangeUser";
		DashboardPage dashboardPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(baseUserName,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickAddNewUserBtn()
				.logout()
				.login(baseUserName, "lengthy password 2");
		
		assertTrue(baseUserName + "is not logged in",dashboardPage.isLoggedInUser(baseUserName));
		
		UserChangePasswordPage passwordChangePage = dashboardPage.clickChangePasswordLink()
																.setCurrentPassword("lengthy password 2")
																.setNewPassword("lengthy password 3")
																.setConfirmPassword("lengthy password 3")
																.clickUpdate();
		
		assertTrue("Password change did not save",passwordChangePage.isSaveSuccessful());
		
		loginPage = passwordChangePage.logout()
						.loginInvalid(baseUserName,"lengthy password 2");
		
		assertTrue("Able to login with old password",loginPage.isloginError());
		
		dashboardPage = loginPage.login(baseUserName, "lengthy password 3");
				
		assertTrue(baseUserName + "is not logged in",dashboardPage.isLoggedInUser(baseUserName));
		
		dashboardPage.logout()
					.login("user", "password")
					.clickManageUsersLink()
					.clickDeleteButton(baseUserName)
					.logout();
		
		
	}
	
	@Test
	public void userPasswordChangeValidationTest(){
		String baseUserName = "passwordChangeValidation";
		DashboardPage dashboardPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(baseUserName,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickAddNewUserBtn()
				.logout()
				.login(baseUserName, "lengthy password 2");
		
		assertTrue(baseUserName + "is not logged in",dashboardPage.isLoggedInUser(baseUserName));
		//wrong current password
		UserChangePasswordPage passwordChangePage = dashboardPage.clickChangePasswordLink()
																.setCurrentPassword("WRONGPASSWORD!!!!")
																.setNewPassword("lengthy password 3")
																.setConfirmPassword("lengthy password 3")
																.clickUpdateInvalid();
		
		assertTrue("Wrong current PW error not displayed",
				passwordChangePage.getErrorText("currentPassword").equals("That was not the correct password."));
		
		//blank new password
		passwordChangePage = passwordChangePage
										.setCurrentPassword("lengthy password 2")
										.setNewPassword("")
										.setConfirmPassword("")
										.clickUpdateInvalid();
		
		assertTrue("Blank new PW error not displayed",
				passwordChangePage.getErrorText("password").equals("You must enter a new password."));
		//different confirm and new passwords
		passwordChangePage = passwordChangePage
										.setCurrentPassword("lengthy password 2")
										.setNewPassword("lengthy password 3")
										.setConfirmPassword("lengthy password 34")
										.clickUpdateInvalid();
		
		assertTrue("Blank confirm PW error not displayed",
				passwordChangePage.getErrorText("password").equals("Passwords do not match."));
		//short password
		passwordChangePage = passwordChangePage
										.setCurrentPassword("lengthy password 2")
										.setNewPassword("password")
										.setConfirmPassword("password")
										.clickUpdateInvalid();
		
		assertTrue("short PW error not displayed",
				passwordChangePage.getErrorText("password").equals("Password has a minimum length of 12."));
		//can you still change password
		passwordChangePage = passwordChangePage
										.setCurrentPassword("lengthy password 2")
										.setNewPassword("lengthy password 3")
										.setConfirmPassword("lengthy password 3")
										.clickUpdate();
		
		assertTrue("Password change did not save",passwordChangePage.isSaveSuccessful());
		
		loginPage = passwordChangePage.logout()
						.loginInvalid(baseUserName, "");
		
		assertTrue("blank password allowed login",loginPage.isloginError());
		
		loginPage = loginPage.loginInvalid(baseUserName,"password");
		
		assertTrue("short password allowed login",loginPage.isloginError());
		
		dashboardPage = loginPage.login(baseUserName,"lengthy password 3");
		
		assertTrue(baseUserName + "is not logged in",dashboardPage.isLoggedInUser(baseUserName));
		
		dashboardPage.logout()
					.login("user", "password")
					.clickManageUsersLink()
					.clickDeleteButton(baseUserName)
					.logout();
		
		
		
	}
	
	
	
}
