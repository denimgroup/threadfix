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
package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import org.openqa.selenium.By;

public class UserTests extends BaseTest {

	@Test
	public void testCreateUser() {
		String userName = "testCreateUser" + getRandomString(3);
        String password = "testCreateUser";
		UserIndexPage userIndexPage = loginPage.login("user", "password")
												.clickManageUsersLink();

		userIndexPage.clickAddUserLink()
                    .enterName(userName,null)
                    .enterPassword(password,null)
                    .enterConfirmPassword(password,null)
                    .clickAddNewUserBtn();
        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));
	}

	@Test 
	public void testUserFieldValidation() {
		UserIndexPage userIndexPage = loginPage.login("user", "password")
											.clickManageUsersLink()
											.clickAddUserLink();

		userIndexPage.enterName("        ",null);
		userIndexPage.enterPassword("  ",null);
		userIndexPage.enterConfirmPassword("  ",null);

		userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();
        sleep(5000);
		assertTrue("Password error not present", userIndexPage.getPasswordError().equals("Password has a minimum length of 12."));

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
		assertTrue("Password matching error is not correct.", userIndexPage.getPasswordMatchError().equals("Passwords do not match."));
	}

    @Test
    public void testCreateDuplicateUser(){
        StringBuilder stringBuilder = new StringBuilder("");
        for (int i = 0; i < 400; i++) { stringBuilder.append('i'); }

        String longInput = stringBuilder.toString();
        // Create a user
        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink();
        userIndexPage.enterName(longInput,null);
        userIndexPage.enterPassword(longInput,null);
        userIndexPage.enterConfirmPassword(longInput,null);

        userIndexPage = userIndexPage.clickAddNewUserBtn();

        String userName = "iiiiiiiiiiiiiiiiiiiiiiiii";
        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
        assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));

        DashboardPage dashboardPage = userIndexPage.logout()
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
        sleep(5000);
        assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));
    }

	@Test
	public void testEditUser() {
		String userName = "testEditUser" + getRandomString(3);
        String password = "testEditUser";
		String editedUserName = "testEditUser" + getRandomString(3);
        String editedPassword = "testCreateUser3";

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
		userIndexPage.clickUpdateUserBtn(userName);
        sleep(500);
		assertTrue("Username changed when edited.", userIndexPage.isUserNamePresent(editedUserName));

		// Test that we are able to log in the second time.
		// This ensures that the password was correctly updated.
		// if this messes up, the test won't complete.
		DashboardPage dashboardPage = userIndexPage.logout()
                                                .login(editedUserName, editedPassword);
        assertTrue("Edited user could not login.", dashboardPage.isLoggedin());
	}

	@Test 
	public void testEditUserFieldValidation() {
		String baseUserName = "testEditUser";
		String userNameDuplicateTest = "duplicate-user";

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

        userIndexPage = userIndexPage.clickManageUsersLink();

		// Test Empty
		userIndexPage = userIndexPage.clickEditLink(baseUserName)
								.enterName("",baseUserName)
								.enterPassword("",baseUserName)
								.enterConfirmPassword("",baseUserName)
								.clickUpdateUserBtnInvalid(baseUserName);

		assertTrue("Name error not present", !userIndexPage.isSaveChangesButtonClickable(baseUserName));

        userIndexPage.clickManageUsersLink();
    }

    @Test
    public void testEditUserValidationWhiteSpace (){
        String userName = "userName"+ getRandomString(5);
        String passWord = "passWord"+ getRandomString(5);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName, null)
                .enterPassword(passWord, null)
                .enterConfirmPassword(passWord, null)
                .clickAddNewUserBtn();

		// Test White Space
		userIndexPage = userIndexPage.clickManageUsersLink()
                                .clickAddUserLink()
                                .enterName("        ", null)
								.enterPassword("             ", null)
								.enterConfirmPassword("             ", null)
								.clickAddNewUserBtn();

        sleep(5000);
		assertTrue("Name error not present", userIndexPage.getNameError().equals("Name is a required field."));
    }

    @Test
    public void testEditUserValidationNoMatching(){
        String userName = "userName"+ getRandomString(5);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                                    .clickManageUsersLink();
		// Test non-matching passwords
		userIndexPage = userIndexPage.clickAddUserLink()
                                    .enterName(userName ,null)
									.enterPassword("lengthy password 1",null)
									.enterConfirmPassword("lengthy password 2", null)
									.clickAddNewUserBtn();

        sleep(5000);
		assertTrue("Password matching error is not correct.", userIndexPage.getPasswordError().equals("Passwords do not match."));

    }

    @Test
    public void testEditUserValidationLength(){

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink();


		// Test length
		userIndexPage = userIndexPage.clickAddUserLink()
                                    .enterName("Test User", null)
									.enterPassword("test",null)
									.enterConfirmPassword("test",null)
									.clickAddNewUserBtn();

        sleep(5000);
		assertTrue("Password length error not present", userIndexPage.getPasswordError().equals("Password has a minimum length of 12."));

    }

    @Test
    public void testEditUserValidationUnique(){
        DashboardPage dashboardPage;
        String userName = "userName"+ getRandomString(5);
        String passWord = "passWord"+ getRandomString(5);

        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(userName, null)
                .enterPassword(passWord, null)
                .enterConfirmPassword(passWord, null)
                .clickAddNewUserBtn();
	
		// Test name uniqueness check
		userIndexPage = userIndexPage
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName,null)
				.enterPassword("lengthy password 2",null)
				.enterConfirmPassword("lengthy password 2",null)
				.clickAddNewUserBtn();

        sleep(5000);
		assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));
		
	}

	@Test
	public void testNavigation() {
		loginPage.login("user", "password")
                 .clickManageUsersLink();
        assertTrue("Could not navigate to User Index Page.",driver.findElements(By.id("newUserModalLink")).size() != 0);
		}

	@Test
	public void testChangePasswordValidation() {
        UserChangePasswordPage changePasswordPage = loginPage.login("user", "password")
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
    public void testDeleteUser(){
        String userName = "testDeleteUser" + getRandomString(3);
        String password = "testDeleteUser";
        UserIndexPage userIndexPage = loginPage.login("user", "password")
                .clickManageUsersLink();

        userIndexPage.clickAddUserLink()
                .enterName(userName,null)
                .enterPassword(password,null)
                .enterConfirmPassword(password,null)
                .clickAddNewUserBtn()
                .clickEditLink(userName)
                .clickDelete(userName);
        assertTrue("Deletion Message not displayed.", userIndexPage.isSuccessDisplayed(userName));
        assertFalse("User still present in user table.", userIndexPage.isUserNamePresent(userName));
    }

	@Test
	public void testChangePassword() {
        String userName = "testChangePassword" + getRandomString(3);
        String password = "testChangePassword";
        String editedPassword = getRandomString(13);

		DashboardPage dashboardPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink()
				.enterName(userName, null)
				.enterPassword(password, null)
				.enterConfirmPassword(password, null)
				.clickAddNewUserBtn()
				.logout()
				.login(userName, password)
				.clickChangePasswordLink()
				.setConfirmPassword(editedPassword)
				.setNewPassword(editedPassword)
				.setCurrentPassword(password)
				.clickUpdate()
				.logout()
				.login(userName, editedPassword);

		assertTrue("Unable to login with new Password.", dashboardPage.isLoggedin());

	}
	
	@Test
	public void testPasswordChangeValidation(){
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
