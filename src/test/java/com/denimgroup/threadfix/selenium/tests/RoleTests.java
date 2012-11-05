package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.RoleCreatePage;
import com.denimgroup.threadfix.selenium.pages.RoleEditPage;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;

public class RoleTests extends BaseTest {

	private WebDriver driver;
	private static LoginPage loginPage;

	RolesIndexPage rolesIndexPage = null;
	RoleCreatePage roleCreatePage = null;

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	/**
	 * Also tests delete
	 */
	@Test
	public void testCreateRoleBasic() {
		// needs to be alphabetically before "Admin" preset role
		String name = "Aa" + getRandomString(15);

		rolesIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickRolesLink()
				.createRole(name);

		assertTrue("The name does not match.", 
				name.equals(rolesIndexPage.getNameContents(0)));

		rolesIndexPage = rolesIndexPage.clickDeleteButton(name);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);
	}
	
	@Test
	public void testEditRole() {
		String name1 = "1" + getRandomString(15);
		String name2 = "2" + getRandomString(15);

		rolesIndexPage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickRolesLink()
				.createRole(name1)
				.clickEditLink(0)
				.clickUpdateRoleButton();

		assertTrue("The name does not match.", 
				name1.equals(rolesIndexPage.getNameContents(0)));
		
		rolesIndexPage = rolesIndexPage.clickEditLink(0)
				.setNameInput(name2)
				.clickUpdateRoleButton();
		
		assertTrue("The name was not updated correctly.", 
				name2.equals(rolesIndexPage.getNameContents(0)));
		
		rolesIndexPage = rolesIndexPage.clickDeleteButton(name2);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);

	}

	@Test
	public void testCreateRoleValidation() {
		String emptyName = "";
		String whiteSpaceName = " \t\n";
		String normalName = getRandomString(15);

		// Test empty string
		
		roleCreatePage = loginPage.login("user", "password").clickConfigurationHeaderLink()
				.clickRolesLink()
				.clickCreateRoleLink()
				.setDisplayNameInput(emptyName)
				.clickCreateRoleButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				"This field cannot be blank".equals(roleCreatePage.getDisplayNameError()));

		// Test whitespace

		roleCreatePage = roleCreatePage.setDisplayNameInput(whiteSpaceName).clickCreateRoleButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				"This field cannot be blank".equals(roleCreatePage.getDisplayNameError()));

		// Test duplicates

		roleCreatePage = roleCreatePage.setDisplayNameInput(normalName)
				.clickCreateRoleButton()
				.clickCreateRoleLink()
				.setDisplayNameInput(normalName)
				.clickCreateRoleButtonInvalid();

		assertTrue("Duplicate name error did not show correctly.", 
				"A group with this name already exists.".equals(roleCreatePage.getDisplayNameError()));

		rolesIndexPage = roleCreatePage.clickBackToIndexLink().clickDeleteButton(normalName);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);
	}
	
	@Test
	public void testSetPermissions() {
		String name = "testName" + getRandomString(10);
		
		RoleCreatePage roleCreatePage = loginPage.login("user", "password")
				.clickConfigurationHeaderLink()
				.clickRolesLink()
				.clickCreateRoleLink()
				.setDisplayNameInput(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					roleCreatePage.getPermissionValue(role));
		}
		
		RoleEditPage roleEditPage = roleCreatePage.clickCreateRoleButton()
				.clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					roleEditPage.getPermissionValue(role));
			roleEditPage.setPermissionValue(role, true);
		}
		
		roleEditPage = roleEditPage.clickUpdateRoleButton()
				.clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", roleEditPage.getPermissionValue(role));
			roleEditPage.setPermissionValue(role, false);
		}
		
		roleEditPage = roleEditPage.clickUpdateRoleButton()
				.clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Role was not turned off correctly.", roleEditPage.getPermissionValue(role));
		}
		
		roleCreatePage = roleEditPage.clickBackToIndexLink()
				.clickDeleteButton(name)
				.clickCreateRoleLink()
				.setDisplayNameInput(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			roleCreatePage.setPermissionValue(role, true);
		}
		
		roleEditPage = roleCreatePage.clickCreateRoleButton()
				.clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", roleEditPage.getPermissionValue(role));
		}
		
		roleEditPage.clickBackToIndexLink().clickDeleteButton(name);
	}
	
	// these tests are to ensure that threadfix cannot enter a state with no users that
	// have permissions to manage users / roles / groups
	
	@Test
	@Ignore
	public void testRemovePermissionsInEditPage() {
		String roleName = "test" + getRandomString(10);
		String admin = "Administrator";
		
		RoleEditPage roleEditPage = loginPage.login("user", "password")
				.clickConfigurationHeaderLink()
				.clickRolesLink()
				.clickEditLink(admin);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Admin role did not have all permissions.", roleEditPage.getPermissionValue(role));
		}
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			roleEditPage = roleEditPage.setPermissionValue(protectedPermission, false)
						.clickUpdateRoleButtonInvalid();
			
			assertTrue("Protected permission was not protected correctly.", 
					"You cannot remove this privilege from this role.".equals(
							roleEditPage.getPermissionError(protectedPermission)));
		}
		
		roleEditPage = roleEditPage.clickBackToIndexLink()
				.clickCreateRoleLink()
				.setDisplayNameInput(roleName)
				.clickCreateRoleButton()
				.clickEditLink(roleName);
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			roleEditPage = roleEditPage.setPermissionValue(protectedPermission, true)
					.clickUpdateRoleButton()
					.clickEditLink(roleName)
					.setPermissionValue(protectedPermission, false)
					.clickUpdateRoleButton()
					.clickEditLink(roleName)
					.setPermissionValue(protectedPermission, true)
					.clickUpdateRoleButton()
					.clickEditLink(admin)
					.setPermissionValue(protectedPermission, false)
					.clickUpdateRoleButton()
					.clickEditLink(roleName)
					.setPermissionValue(protectedPermission, false)
					.clickUpdateRoleButtonInvalid();

			assertTrue("Protected permission was not protected correctly.", 
					"You cannot remove this privilege from this role.".equals(
							roleEditPage.getPermissionError(protectedPermission)));
			
			roleEditPage.setPermissionValue(protectedPermission, true);
		}
		
		roleEditPage = roleEditPage.clickBackToIndexLink().clickEditLink(admin);
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			roleEditPage.setPermissionValue(protectedPermission, true);
		}
		
		roleEditPage.clickUpdateRoleButton().clickDeleteButton(roleName);
	}
	
	/**
	 * Try to set users for the role such that no one will have admin permissions
	 */
	@Test
	public void testRemoveUsersFromRole() {
		// Test on admin role
		// if it breaks then so be it
		
		// Make sure that admin is the only role
		
		// try to set users to none
		// fail
		
		// create another role with the important permissions and a user
		
		// set users for original role to none
		// success
		
		// set users for new role to none
		// failure
		
	}
	
	/**
	 * Try to set roles for the users such that no one will have admin permissions
	 */
	@Test
	public void testRemoveRolesFromUser() {
		
	}
	
	/**
	 * Try to delete the last users with admin permissions
	 */
	@Test
	public void testDeleteUsers() {
		
	}
	
	/**
	 * Try to delete the last roles with admin permissions
	 */
	@Test
	public void testDeleteRoles() {
		
	}
}
