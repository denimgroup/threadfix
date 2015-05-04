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

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.UserChangePasswordPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class UserIT extends BaseDataTest {

    private UserIndexPage userIndexPage;

    @Before
    public void initialize() {
        userIndexPage = loginPage.defaultLogin()
                .clickManageUsersLink();
    }

    //===========================================================================================================
    // Creation, Deletion, and Editing
    //===========================================================================================================

	@Test
	public void testCreateUser() {
		String userName = getName();
        String password = "testCreateUser";

		userIndexPage.createUser(userName, "", password);

        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
		assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));
	}

    @Test
    public void testCreateTwoUsersWithoutRefresh() {
        String userName = getName();
        String password = "testCreateUser";

        String secondUserName = getName();

        userIndexPage.createUser(userName, "", password);

        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
        assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));

        userIndexPage.createUser(secondUserName,"",password);

        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(secondUserName));
        assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(secondUserName));
        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
    }

    @Test
    public void testEditUserName() {
        String userName = getName();
        String editedUserName = getName();
        String password = getRandomString(15);
        String editedPassword = getRandomString(15);

        userIndexPage.createUser(userName, "", password);

        DashboardPage dashboardPage= userIndexPage.logout()
                .login(userName, password);

        assertTrue("New user was not able to login.", dashboardPage.isLoggedin());

        dashboardPage.logout()
                .defaultLogin()
                .clickManageUsersLink()
                .editUser(userName, editedUserName, "", editedPassword)
                .logout()
                .login(editedUserName, editedPassword);

        assertTrue("Edited user was not able to login.", dashboardPage.isLoggedin());
    }

    @Test
    public void testEditPassword() {
        String userName = getName();
        String password = getRandomString(15);
        String editedPassword = getRandomString(15);

        assertFalse("User was already in the table.", userIndexPage.isUserNamePresent(userName));

        UserChangePasswordPage userChangePasswordPage = userIndexPage.createUser(userName, "", password)
                .logout()
                .login(userName, password)
                .clickChangePasswordLink()
                .setCurrentPassword(password)
                .setNewPassword(editedPassword)
                .setConfirmPassword(editedPassword)
                .clickUpdate();


        DashboardPage dashboardPage = userChangePasswordPage.logout()
                .login(userName, editedPassword);

        assertTrue("Edited user could not login.", dashboardPage.isLoggedin());
    }

    @Test
    public void testDeleteUser(){
        String userName = getName();
        String password = "testDeleteUser";

        userIndexPage.createUser(userName,"",password)
                .clickUserLink(userName)
                .clickDelete(userName);

        assertTrue("Deletion Message not displayed.", userIndexPage.isSuccessDisplayed(userName));
        assertFalse("User still present in user table.", userIndexPage.isUserNamePresent(userName));
    }

    @Test
    public void testEditMultipleUsers() {
        String userName1 = getName();
        String password1 = "testEditMultipleUsers";
        String userName2 = getName();
        String password2 = "testEditMultipleUsers2";
        String changedPassword = "changedPasswordTestMultipleUsers";
        String changedName = getName();
        String displayCssId = "displayName" + changedName;

        userIndexPage.createUser(userName1, "", password1)
                .createUser(userName2, "", password2);

        userIndexPage.editUser(userName1, userName1,changedName,password1)
                .editUser(userName2, userName2,"",changedPassword);

        assertTrue("Second user's display name was changed to the first user's name when attempting to change only password.",
                driver.findElements(By.id(displayCssId)).size() < 2);
    }

    @Test
    public void testAddUserWithDisplayName() {
        String userName = getName();
        String displayName = getName();
        String password = getName();

        userIndexPage.createUser(userName, displayName, password)
                .refreshPage();

        assertTrue("User with display name was not added correctly.",
                driver.findElement(By.id("displayName" + displayName)).isDisplayed());
    }

    @Test
    public void testAddDisplayNameToUser() {
        String userName = getName();
        String displayName = getName();
        String password = getName();

        userIndexPage.createUser(userName, "", password)
                .editUser(userName, userName, displayName, password)
                .refreshPage();

        assertTrue("User with display name was not added correctly.",
                driver.findElement(By.id("displayName" + displayName)).isDisplayed());
    }

    //===========================================================================================================
    // Validation
    //===========================================================================================================

    @Test
    public void testUserFieldValidation() {
        userIndexPage.clickAddUserLink()
                .setName("        ")
                .setPassword("  ")
                .setConfirmPassword("  ")
                .clickAddNewUserBtnInvalid();

        sleep(5000);

        assertTrue("Name is required error was not present.",
                userIndexPage.getRequiredNameError().equals("Name is required."));
        assertTrue("Password is required error was not present.",
                userIndexPage.getPasswordRequiredError().equals("Password is required."));
        assertTrue("Confirm Password is required error was not present.",
                userIndexPage.getConfirmPasswordRequiredError().equals("Confirm Password is required."));

        // Test length
        userIndexPage.setName("Test User");
        userIndexPage.setPassword("test");
        userIndexPage.setConfirmPassword("test");

        userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();

        assertTrue("Password length error not present", userIndexPage.getPasswordLengthError().equals("8 characters needed"));

        // Test non-matching passwords
        userIndexPage.setName("new name");
        userIndexPage.setPassword("lengthy password 1");
        userIndexPage.setConfirmPassword("lengthy password 2");
        userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();
        assertTrue("Password matching error is not correct.", userIndexPage.getPasswordMatchError().equals("Passwords do not match."));
    }

    @Test
    public void testCreateDuplicateUser(){
        String userName = getName();
        String password = getRandomString(15);

        userIndexPage.createUser(userName, "", password);

        assertTrue("User name was not present in the table.", userIndexPage.isUserNamePresent(userName));
        assertTrue("Success message was not displayed.", userIndexPage.isSuccessDisplayed(userName));

        DashboardPage dashboardPage = userIndexPage.logout()
                .login(userName, password);

        assertTrue("user: "+userName+" was not logged in.",dashboardPage.isLoggedInUser(userName));

        userIndexPage = dashboardPage.logout()
                .defaultLogin()
                .clickManageUsersLink()
                .clickAddUserLink();
        // Test name uniqueness check

        userIndexPage.setName(userName);
        userIndexPage.setPassword("dummy password");
        userIndexPage.setConfirmPassword("dummy password");

        userIndexPage = userIndexPage.clickAddNewUserBtnInvalid();
        sleep(5000);
        assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));
    }

    @Test
    public void testEditPasswordValidation() {
        UserChangePasswordPage changePasswordPage = userIndexPage.clickChangePasswordLink()
                .setCurrentPassword(" ")
                .setNewPassword("password1234")
                .setConfirmPassword("password1234")
                .clickUpdateInvalid();

        assertTrue("Password is required error was not present.",
                changePasswordPage.getPasswordRequiredError().equals("Password is required."));

        changePasswordPage = changePasswordPage.setCurrentPassword("password")
                .setNewPassword("                     ")
                .setConfirmPassword("password1234")
                .clickUpdateInvalid();

        assertTrue("Password match error not present",
                changePasswordPage.getErrorText("passwordMatchError").contains("Passwords do not match."));

        changePasswordPage = changePasswordPage.setCurrentPassword("password")
                .setConfirmPassword("                  ")
                .setNewPassword("password1234")
                .clickUpdateInvalid();

        assertTrue("Password match error not present",
                changePasswordPage.getErrorText("passwordMatchError").contains("Passwords do not match."));

        changePasswordPage = changePasswordPage.setCurrentPassword("password")
                .setConfirmPassword("      ")
                .setNewPassword("password124")
                .clickUpdateInvalid();

        assertTrue("Field required error missing",
                changePasswordPage.getErrorText("confirmRequiredError").contains("This field is required."));

        changePasswordPage.logout();
    }

	@Test
	public void testEditUserFieldValidation() {
		String baseUserName = getName();
		String userNameDuplicateTest = getName();

		// Set up the two User objects for the test

		userIndexPage.createUser(baseUserName, "", "lengthy password 2");

        userIndexPage = userIndexPage.clickManageUsersLink()
                .createUser(userNameDuplicateTest, "", "lengthy password 2");

		// Test submission with no changes
		userIndexPage = userIndexPage.clickManageUsersLink()
                .clickUserLink(baseUserName)
                .clickUpdateUserBtn();
		assertTrue("User name was not present in the table.",userIndexPage.isUserNamePresent(baseUserName));

        userIndexPage = userIndexPage.clickManageUsersLink();

		// Test Empty
		userIndexPage = userIndexPage.clickUserLink(baseUserName)
                .setName("")
                .setPassword("")
                .setConfirmPassword("")
                .clickUpdateUserBtnInvalid(baseUserName);

		assertTrue("Name error not present", userIndexPage.isSaveChangesButtonClickable(baseUserName));
    }

    @Test
    public void testEditUserValidationWhiteSpace(){
        String userName = getName();
        String passWord = getName();

        userIndexPage.createUser(userName, "", passWord);

		// Test White Space
		userIndexPage = userIndexPage.clickManageUsersLink()
                .createUser("        ", "", "             ");

        sleep(5000);
		assertTrue("Name error not present", userIndexPage.getRequiredNameError().equals("Name is required."));
    }

    @Test
    public void testEditUserValidationPasswordMatching(){
        String userName = getName();

		userIndexPage.clickAddUserLink()
                .setName(userName)
                .setPassword("lengthy password 1")
                .setConfirmPassword("lengthy password 2")
                .clickAddNewUserBtn();

		assertTrue("Password matching error is not correct.", userIndexPage.getPasswordMatchError().equals("Passwords do not match."));

    }

    @Test
    public void testEditUserValidationLength(){
        userIndexPage.createUser("Test User","","test");

		assertTrue("Password length error not present", userIndexPage.getPasswordLengthError().equals("8 characters needed"));
    }

    @Test
    public void testEditUserValidationUnique(){
        String userName = getName();
        String passWord = getName();

        userIndexPage.createUser(userName,"",passWord)
                .createUser(userName, "", "lengthy password 2");

		assertTrue("Name uniqueness error is not correct.", userIndexPage.getNameError().equals("That name is already taken."));
		
	}

    //===========================================================================================================
    // Other
    //===========================================================================================================

	@Test
	public void testNavigation() {
        assertTrue("Could not navigate to User Index Page.",driver.findElements(By.id("newUserModalLink")).size() != 0);
	}

    @Test
    public void testDisplayNameOnComment() {
        initializeTeamAndAppWithIbmScan();
        String userName = getName();
        String displayName = getName();
        String password = getName();

        userIndexPage.createUser(userName,displayName,password)
                .clickUserLink(userName)
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess("Administrator")
                .clickUpdateUserBtn();

        ApplicationDetailPage applicationDetailPage = userIndexPage.logout()
                .login(userName, password)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(getName())
                .clickModalSubmit()
                .refreshPage();

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790");

        assertTrue("Display name was not used on comment.",
                driver.findElement(By.id("commentUser0")).getText().equals(displayName));
    }

    @Test
    public void testDisplayNameHeader() {
        String userName = getName();
        String displayName = getName();
        String password = getName();

        userIndexPage.createUser(userName,displayName,password)
                .logout()
                .login(userName, password);

        assertTrue("Display name is not shown in header.",
                driver.findElement(By.id("tabUserAnchor")).getText().contains(displayName));
    }
}
