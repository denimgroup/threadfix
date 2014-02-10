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

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.RoleCreatePage;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;
import com.denimgroup.threadfix.selenium.pages.UserIndexPage;

public class RoleTests extends BaseTest {

	public RoleTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}


	private RemoteWebDriver driver;
	private static LoginPage loginPage;

	RolesIndexPage rolesIndexPage = null;
	RoleCreatePage roleCreatePage = null;

	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
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
				.setRoleName(name,null)
				.clickSaveRole(null);

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(name));
		assertTrue("Validation message is Present.",rolesIndexPage.isCreateValidationPresent(name));

		rolesIndexPage = rolesIndexPage.clickDeleteButton(name);
		assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(name));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(name));
	}
	
	@Test
	public void testEditRole() {
		String name1 = "1" + getRandomString(15);
		String name2 = "2" + getRandomString(15);

		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(name1,null)
				.clickSaveRole(null)
				.clickEditLink(name1)
				.clickSaveRole(name1);

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(name1));
		assertTrue("Validation message is Present.",rolesIndexPage.isEditValidationPresent(name1));
		
		rolesIndexPage = rolesIndexPage.clickEditLink(name1)
				.setRoleName(name2,name1)
				.clickSaveRole(name1);
		
		assertTrue("Role not Edited Correctly.", rolesIndexPage.isNamePresent(name2));
		assertTrue("Validation message is Present.",rolesIndexPage.isEditValidationPresent(name2));
		
		rolesIndexPage = rolesIndexPage.clickDeleteButton(name2);

		assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(name2));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(name2));

	}

	@Test
	public void testCreateRoleValidation() {
		String emptyName = "";
		String whiteSpaceName = "     ";
		String normalName = getRandomString(15);

		// Test empty string
		
		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(emptyName,null)
				.clickSaveRoleInvalid(null);

		assertTrue("Blank field error didn't show correctly.", 
				rolesIndexPage.getNameError().contains("This field cannot be blank"));

		// Test whitespace

		rolesIndexPage = rolesIndexPage.setRoleName(whiteSpaceName,null).clickSaveRoleInvalid(null);

		assertTrue("Blank field error didn't show correctly.", 
				rolesIndexPage.getNameError().contains("This field cannot be blank"));

		// Test duplicates

		rolesIndexPage = rolesIndexPage.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(normalName,null)
				.clickSaveRole(null)
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(normalName,null)
				.clickSaveRoleInvalid(null);

		assertTrue("Duplicate name error did not show correctly.",
				rolesIndexPage.getDisplayNameError().contains("A role with this name already exists."));

		rolesIndexPage = rolesIndexPage.clickDeleteButton(normalName);

		assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(normalName));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(normalName));
	}
	
	@Test
	public void testSetPermissions() {
		String name = "testName" + getRandomString(10);
		
		rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(name,null);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					rolesIndexPage.getPermissionValue(role,null));
		}
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Checkbox was set to true when it shouldn't have been.", 
					rolesIndexPage.getPermissionValue(role,null));
			rolesIndexPage.setPermissionValue(role, true, null);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(null)
									.clickEditLink(name);
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", rolesIndexPage.getPermissionValue(role,name));
			rolesIndexPage.setPermissionValue(role, false,name);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(name)
									.clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertFalse("Role was not turned off correctly.", rolesIndexPage.getPermissionValue(role,name));
		}
		rolesIndexPage = rolesIndexPage.clickSaveRole(name)
									.clickDeleteButton(name)
									.clickCreateRole()
									.setRoleName(name,null);
		
		for (String role : Role.ALL_PERMISSIONS) {
			rolesIndexPage.setPermissionValue(role, true, null);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(null).clickEditLink(name);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Role was not turned on correctly.", rolesIndexPage.getPermissionValue(role,name));
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(name)
				.clickDeleteButton(name);
		assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(name));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(name));
	}
	
	// these tests are to ensure that threadfix cannot enter a state with no users that
	// have permissions to manage users / roles / groups
	
	@Ignore
	@Test
	public void testRemoveRolesFromUser() {
		String admin = "Administrator";
		
		 UserIndexPage userIndexPage = loginPage.login("user", "password")
				.clickManageUsersLink()
				.clickAddUserLink();
		 userIndexPage.enterName("RoleRemoval",null)
		 				.enterPassword("passwordpassword", null)
		 				.enterConfirmPassword("passwordpassword", null)
		 				.chooseRoleForGlobalAccess(admin, null)
		 				.clickAddNewUserBtn()
		 				.clickEditLink("user")
		 				.chooseRoleForGlobalAccess("Read Access", "user")
		 				.clickUpdateUserBtn("user");
		 
		
		rolesIndexPage = userIndexPage.clickManageRolesLink()
				.clickEditLink(admin);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Admin role did not have all permissions.", rolesIndexPage.getPermissionValue(role,admin));
		}
		
		for (String protectedPermission : Role.PROTECTED_PERMISSIONS) {
			rolesIndexPage.setPermissionValue(protectedPermission, false,admin);
		}	
		rolesIndexPage.clickSaveRoleInvalid(admin);
		assertTrue("Protected permission was not protected correctly.", 
				rolesIndexPage.getDisplayNameError().contains("You cannot remove the Manage Users privilege from this role."));
		
		rolesIndexPage = rolesIndexPage.clickCloseModal()
									.clickManageRolesLink()
									.clickEditLink(admin);
		
		for (String role : Role.ALL_PERMISSIONS) {
			assertTrue("Admin role did not have all permissions.", rolesIndexPage.getPermissionValue(role,admin));
		}
		
		rolesIndexPage.clickManageUsersLink()
						.clickEditLink("user")
						.chooseRoleForGlobalAccess(admin, "user")
						.clickUpdateUserBtn("user")
						.clickDeleteButton("RoleRemoval");
		
	}
	@Ignore
	@Test
	public void testDeleteRoleWithUserAttached(){
		String roleName = "test" + getRandomString(10);
		String roleName2 = "test" + getRandomString(10);
		rolesIndexPage = loginPage.login("user", "password")
								.clickManageRolesLink();
		
		rolesIndexPage = rolesIndexPage.clickCreateRole()
				.setRoleName(roleName,null)
				.clickSaveRole(null)
				.clickCreateRole()
				.setRoleName(roleName2,null)
				.clickSaveRole(null)
				.clickEditLink(roleName);
		
		for (String protectedPermission : Role.ALL_PERMISSIONS) {
			rolesIndexPage = rolesIndexPage.setPermissionValue(protectedPermission, true,roleName);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(roleName)
									.clickEditLink(roleName2);
		
		for (String protectedPermission : Role.ALL_PERMISSIONS) {
			rolesIndexPage = rolesIndexPage.setPermissionValue(protectedPermission, true,roleName2);
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole(roleName2)
					.clickManageUsersLink()
					.clickEditLink("user")
					.chooseRoleForGlobalAccess(roleName, "user")
					.clickUpdateUserBtn("user")
					.clickManageRolesLink()
					.clickDeleteButton(roleName);
		
		
		assertTrue("Role was not removed.",rolesIndexPage.isNamePresent(roleName));
		
		rolesIndexPage = rolesIndexPage.clickManageUsersLink()
									.clickEditLink("user")
									.chooseRoleForGlobalAccess(roleName2, "user")
									.clickUpdateUserBtn("user")
									.clickManageRolesLink()
									.clickDeleteButton(roleName);
		
		assertFalse("Role was not removed.",rolesIndexPage.isNamePresent(roleName));
		
		rolesIndexPage = rolesIndexPage.clickManageUsersLink()
				.clickEditLink("user")
				.chooseRoleForGlobalAccess("Administrator", "user")
				.clickUpdateUserBtn("user")
				.clickManageRolesLink()
				.clickDeleteButton(roleName2);
		
		assertFalse("Role was not removed.",rolesIndexPage.isNamePresent(roleName2));
	}
	
	/**
	 * Try to set users for the role such that no one will have admin permissions
	 * will be dangerous to run on regression(if it fails all other tests could fail)
	 */
	@Ignore
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
	 * will be dangerous to run on regression(if it fails all other tests could fail)
	 */
	@Ignore
	@Test
	public void testDeleteUsers() {
		
	}
	
	
	

}
