package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.RoleCreatePage;
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

		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setNewRoleName(name)
				.clickSaveRole()
				.clickManageRolesLink();

		assertTrue("The name does not match.", 
				name.equals(rolesIndexPage.getNameContents(0)));

		rolesIndexPage = rolesIndexPage.clickDeleteButton(name);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);
	}
	
	@Test
	public void testEditRole() {
		String name1 = "1" + getRandomString(15);
		String name2 = "2" + getRandomString(15);

		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setNewRoleName(name1)
				.clickSaveRole()
				.clickManageRolesLink()
				.clickEditLink(0)
				.clickUpdateRoleButton(0);

		assertTrue("The name does not match.", 
				name1.equals(rolesIndexPage.getNameContents(0)));
		
		rolesIndexPage = rolesIndexPage.clickEditLink(0)
				.setRoleName(name2,0)
				.clickUpdateRoleButton(0);
		
		assertTrue("The name was not updated correctly.", 
				name2.equals(rolesIndexPage.getNameContents(0)));
		
		rolesIndexPage = rolesIndexPage.clickDeleteButton(name2);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);

	}
//had to take \n out of whitespace because the modals do not like enter yet fails due to no whitespace validation yet
	@Test
	public void testCreateRoleValidation() {
		String emptyName = "";
		String whiteSpaceName = "     ";
		String normalName = getRandomString(15);

		// Test empty string
		
		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(emptyName)
				.clickCreateRoleButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				rolesIndexPage.getDisplayNameError().contains("This field cannot be blank"));

		// Test whitespace

		rolesIndexPage = rolesIndexPage.setRoleName(whiteSpaceName).clickCreateRoleButtonInvalid();

		assertTrue("Blank field error didn't show correctly.", 
				rolesIndexPage.getDisplayNameError().contains("This field cannot be blank"));

		// Test duplicates

		rolesIndexPage = rolesIndexPage.setRoleName(normalName)
				.clickSaveRole()
				.clickManageRolesLink()
				.clickCreateRole()
				.setNewRoleName(normalName)
				.clickCreateRoleButtonInvalid();

		assertTrue("Duplicate name error did not show correctly.",
				rolesIndexPage.getDisplayNameError().contains("A role with this name already exists."));

		rolesIndexPage = rolesIndexPage.clickDeleteButton(normalName);

		assertTrue("Item still present.", rolesIndexPage.getNumRows() == 2);
	}
	
	@Test
	public void testSetPermissions() {
		String name = "testName" + getRandomString(10);
		
		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setNewRoleName(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					rolesIndexPage.getPermissionValue(role));
		}
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					rolesIndexPage.getPermissionValue(role));
			rolesIndexPage.setPermissionValue(role, true);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole().clickManageRolesLink().clickEditLink(2);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", rolesIndexPage.getPermissionValue(role,2));
			rolesIndexPage.setPermissionValue(role, false,2);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(2).clickManageRolesLink().clickEditLink(2);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Role was not turned off correctly.", rolesIndexPage.getPermissionValue(role,2));
		}
		rolesIndexPage = rolesIndexPage.clickSaveRole(2)
									.clickDeleteButton(name)
									.clickCreateRole()
									.setNewRoleName(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			rolesIndexPage.setPermissionValue(role, true);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole().clickManageRolesLink().clickEditLink(2);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", rolesIndexPage.getPermissionValue(role,2));
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(2)
				.clickManageRolesLink()
				.clickDeleteButton(name);
	}
	
	// these tests are to ensure that threadfix cannot enter a state with no users that
	// have permissions to manage users / roles / groups
	
	@Test
	//@Ignore
	public void testRemoveRolesFromUser() {
		String roleName = "test" + getRandomString(10);
		String admin = "Administrator";
		
		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickEditLink(0);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Admin role did not have all permissions.", rolesIndexPage.getPermissionValue(role,0));
		}
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			rolesIndexPage.setPermissionValue(protectedPermission, false,0);
		}	
		rolesIndexPage.clickSaveRole(0);
		assertTrue("Protected permission was not protected correctly.", 
				rolesIndexPage.getAlert().contains("You cannot remove the Manage Users privilege from this role."));
		
		rolesIndexPage = rolesIndexPage.clickCloseModal()
									.clickCreateRole()
									.setNewRoleName(roleName)
									.clickSaveRole()
									.clickEditLink(roleName);
		
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			rolesIndexPage = rolesIndexPage.setPermissionValue(protectedPermission, true,1)
					.clickSaveRole(1)
					.clickEditLink(1)
					.setPermissionValue(protectedPermission, false)
					.clickSaveRole(1)
					.clickEditLink(1)
					.setPermissionValue(protectedPermission, true)
					.clickSaveRole(1)
					.clickEditLink(admin)
					.setPermissionValue(protectedPermission, false)
					.clickSaveRole(1)
					.clickEditLink(1)
					.setPermissionValue(protectedPermission, false)
					.clickUpdateRoleButtonInvalid(1);

			assertTrue("Protected permission was not protected correctly.", 
					"You cannot remove this privilege from this role.".contains(
							rolesIndexPage.getAlert()));
			
			rolesIndexPage.setPermissionValue(protectedPermission, true);
		}
		
		rolesIndexPage = rolesIndexPage.clickCloseModal().clickEditLink(0);
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			rolesIndexPage.setPermissionValue(protectedPermission, true);
		}
		
		rolesIndexPage.clickSaveRole(0).clickDeleteButton(roleName);
	}
	
	/**
	 * Try to set users for the role such that no one will have admin permissions
	 */
	//user page is not complete yet
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
	 * Try to delete the last users with admin permissions
	 */
	//user page is not complete yet
	@Test
	public void testDeleteUsers() {
		
	}
	

}
