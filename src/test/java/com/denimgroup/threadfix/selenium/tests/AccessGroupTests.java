package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.selenium.pages.GroupCreatePage;
import com.denimgroup.threadfix.selenium.pages.GroupEditPage;
import com.denimgroup.threadfix.selenium.pages.GroupUserConfigPage;
import com.denimgroup.threadfix.selenium.pages.GroupsIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;

public class AccessGroupTests extends BaseTest {

	private WebDriver driver;
	private static LoginPage loginPage;

	GroupsIndexPage groupsIndexPage = null;
	GroupCreatePage groupCreatePage = null;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@Test
	public void testCreateGroupBasic() {
		String name = getRandomString(15);

		groupsIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(name, null, null);

		assertTrue("The name does not match.", 
				name.equals(groupsIndexPage.getNameContents(0)));

		groupsIndexPage = groupsIndexPage.clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);
	}
	
	@Test
	public void testUserConfigPage() {
		
		String name = "test group";
		// Data setup
		
		String[] userNames = new String[] {"user1", "user2", "user3", "user4"};
		
		int count = 1;
		for (int i = 0; i < userNames.length; i++) { count *= 2; }
		
		//Login && create users
		
		UserIndexPage userIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickManageUsersLink();
		
		for (String userName : userNames) {
			userIndexPage = userIndexPage.clickAddUserLink()
					.setNameInput(userName)
					.setPasswordConfirmInput("testpassword")
					.setPasswordInput("testpassword")
					.clickAddUserButton()
					.clickBackToMenuLink();
		}
				
		GroupUserConfigPage userConfigPage = userIndexPage.clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(name, null, null)
				.clickUserConfigLink(0);
		
		// Test all combinations of users
		// TODO maybe implement a less bit-twiddly way of doing powersets
		// the (i >> j) % 2 idiom extracts the value of the jth bit of i
		for (int i = 0; i < count; i++) {
			
			for (int j = 0; j < userNames.length; j++) {
				if (userConfigPage.isChecked(userNames[j]) != ((i >> j) % 2 == 1)) {
					userConfigPage.toggleUserIdBox(userNames[j], (i >> j) % 2 == 1);
				}
			}
			
			userConfigPage = userConfigPage.clickSubmitButton().clickUserConfigLink(0);
			
			for (int j = 0; j < userNames.length; j++) {
				assertTrue("Box was not checked correctly.",
						userConfigPage.isChecked(userNames[j]) == ((i >> j) % 2 == 1));
			}
		}
		
		userIndexPage = userConfigPage.clickSubmitButton()
				.clickDeleteButton(0)
				.clickBackToMenuLink()
				.clickManageUsersLink();
		
		for (String userName : userNames) {
			userIndexPage = userIndexPage.clickUserNameLink(userName).clickDeleteLink();
			assertFalse("The user was not deleted correctly.", userIndexPage.isUserNamePresent(userName));
		}
		
		groupsIndexPage = userIndexPage.clickConfigurationHeaderLink().clickGroupsLink();
		
		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);
	}

	@Test
	public void testEditGroup() {
		String name1 = "1" + getRandomString(15);
		String name2 = "2" + getRandomString(15);

		groupsIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(name1, null, null)
				.clickEditLink(0)
				.clickUpdateGroupButton();

		assertTrue("The name does not match.", 
				name1.equals(groupsIndexPage.getNameContents(0)));
		
		groupsIndexPage = groupsIndexPage.clickEditLink(0)
				.setNameInput(name2)
				.clickUpdateGroupButton();
		
		assertTrue("The name was not updated correctly.", 
				name2.equals(groupsIndexPage.getNameContents(0)));
		
		groupsIndexPage = groupsIndexPage.createGroup(name1, null, null)
				.clickEditLink(1)
				.setParentGroup(name1)
				.clickUpdateGroupButton();
		
		assertTrue("The parent group was not updated correctly.", 
				name1.equals(groupsIndexPage.getParentGroupName(1)));
		
		groupsIndexPage = groupsIndexPage.clickOrganizationHeaderLink()
				.clickAddOrganizationButton()
				.setNameInput(name1)
				.clickSubmitButtonValid()
				.clickConfigurationHeaderLink()
				.clickGroupsLink()
				.clickEditLink(1)
				.setTeamSelect(name1)
				.clickUpdateGroupButton();
		
		assertTrue("The team was not updated correctly.", 
				name1.equals(groupsIndexPage.getTeamName(1)));
		
		groupsIndexPage = groupsIndexPage.clickDeleteButton(0).clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);

		groupsIndexPage.clickOrganizationHeaderLink().clickOrganizationLink(name1).clickDeleteButton();
	}

	@Test
	public void testCycleDetection() {
		String name1 = "1" + getRandomString(15);
		String name2 = "2" + getRandomString(15);
		String name3 = "3" + getRandomString(15);
		String name4 = "4" + getRandomString(15);

		// 2 nodes

		GroupEditPage groupEditPage = loginPage.login("user", "password")
				.clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(name1, null, null)
				.createGroup(name2, null, name1)
				.clickEditLink(0)
				.setParentGroup(name2)
				.clickUpdateGroupButtonInvalid();

		assertTrue("The cycle error is not present.", 
				"Choose another group. This one leads to a cycle."
				.equals(groupEditPage.getParentGroupIdError()));

		// 3 nodes

		groupEditPage = groupEditPage.clickBackToIndexLink()
				.createGroup(name3, null, name2)
				.clickEditLink(0)
				.setParentGroup(name3)
				.clickUpdateGroupButtonInvalid();

		assertTrue("The cycle error is not present.", 
				"Choose another group. This one leads to a cycle."
				.equals(groupEditPage.getParentGroupIdError()));

		// 4 nodes

		groupEditPage = groupEditPage.clickBackToIndexLink()
				.createGroup(name4, null, name3)
				.clickEditLink(0)
				.setParentGroup(name4)
				.clickUpdateGroupButtonInvalid();

		assertTrue("The cycle error is not present.", 
				"Choose another group. This one leads to a cycle."
				.equals(groupEditPage.getParentGroupIdError()));

		groupsIndexPage = groupEditPage.clickBackToIndexLink()
				.clickDeleteButton(0)
				.clickDeleteButton(0)
				.clickDeleteButton(0)
				.clickDeleteButton(0);

		assertTrue("Items still present.", groupsIndexPage.getNumRows() == 0);
	}

	@Test
	public void testCreateGroupValidation() {
		String emptyName = "";
		String whiteSpaceName = " \t\n";
		String normalName = getRandomString(15);

		// Test empty string

		groupCreatePage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickGroupsLink()
				.clickCreateGroupLink()
				.setNameInput(emptyName)
				.clickCreateGroupButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				"This field cannot be blank".equals(groupCreatePage.getNameError()));

		// Test whitespace

		groupCreatePage = groupCreatePage.setNameInput(whiteSpaceName).clickCreateGroupButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				"This field cannot be blank".equals(groupCreatePage.getNameError()));

		// Test duplicates

		groupCreatePage = groupCreatePage.setNameInput(normalName)
				.clickCreateGroupButton()
				.clickSubmitButton()
				.clickCreateGroupLink()
				.setNameInput(normalName)
				.clickCreateGroupButtonInvalid();

		assertTrue("Duplicate name error did not show correctly.", 
				"A group with this name already exists.".equals(groupCreatePage.getNameError()));

		groupsIndexPage = groupCreatePage.clickBackToIndexLink().clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);
	}

	@Test
	public void testCreateGroupWithTeam() {
		String name = getRandomString(15);
		String teamName = getRandomString(15);

		groupsIndexPage = loginPage.login("user", "password").clickAddOrganizationButton()
				.setNameInput(teamName)
				.clickSubmitButtonValid()
				.clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(name, teamName, null);

		assertTrue("The name does not match.", 
				name.equals(groupsIndexPage.getNameContents(0)));

		assertTrue("The team name does not match.",
				teamName.equals(groupsIndexPage.getTeamName(0)));

		groupsIndexPage = groupsIndexPage.clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);

		groupsIndexPage.clickOrganizationHeaderLink().clickOrganizationLink(teamName).clickDeleteButton();
	}

	@Test
	public void testCreateGroupWithParentGroup() {
		String childName = "child" + getRandomString(15);
		String parentName = "parent" + getRandomString(15);

		groupsIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(parentName, null, null)
				.createGroup(childName, null, parentName);

		assertTrue("The name does not match.", 
				childName.equals(groupsIndexPage.getNameContents(0)));

		assertTrue("The parent group name does not match.",
				parentName.equals(groupsIndexPage.getParentGroupName(0)));

		assertTrue("The parent group name does not match.",
				parentName.equals(groupsIndexPage.getNameContents(1)));

		groupsIndexPage = groupsIndexPage.clickDeleteButton(0).clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);
	}

	@Test
	public void testCreateGroupWithAll() {
		String childName  = "child" + getRandomString(15);
		String parentName = "parent" + getRandomString(15);
		String teamName   = "team" + getRandomString(15);

		groupsIndexPage = loginPage.login("user", "password").clickAddOrganizationButton()
				.setNameInput(teamName)
				.clickSubmitButtonValid()
				.clickConfigurationHeaderLink()
				.clickGroupsLink()
				.createGroup(parentName, null, null)
				.createGroup(childName, teamName, parentName);

		assertTrue("The name does not match.", 
				childName.equals(groupsIndexPage.getNameContents(0)));

		assertTrue("The parent group name does not match.",
				parentName.equals(groupsIndexPage.getParentGroupName(0)));

		assertTrue("The team name does not match.",
				teamName.equals(groupsIndexPage.getTeamName(0)));

		assertTrue("The parent group name does not match.",
				parentName.equals(groupsIndexPage.getNameContents(1)));

		groupsIndexPage = groupsIndexPage.clickDeleteButton(0)
				.clickDeleteButton(0);

		assertTrue("Item still present.", groupsIndexPage.getNumRows() == 0);
		
		groupsIndexPage.clickOrganizationHeaderLink()
				.clickOrganizationLink(teamName)
				.clickDeleteButton();
	}
}
