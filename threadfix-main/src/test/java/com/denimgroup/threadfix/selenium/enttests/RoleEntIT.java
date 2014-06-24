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

package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class RoleEntIT extends BaseIT {

	@Test
	public void testCreateRole() {
        String roleName = getRandomString(8);

		RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName)
				.clickSaveRole();

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(roleName));
		assertTrue("Validation message is Present.",rolesIndexPage.isCreateValidationPresent(roleName));
	}

    @Test
    public void testDeleteRole() {
        String roleName = getRandomString(8);

        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .clickSaveRole();

        assertTrue("Role not added.", rolesIndexPage.isNamePresent(roleName));

        rolesIndexPage = rolesIndexPage.clickDeleteButton(roleName);

        assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(roleName));
        assertFalse("Role not removed.", rolesIndexPage.isNamePresent(roleName));
    }

	@Test
	public void testEditRole() {
		String originalRoleName = getRandomString(8);
		String editedRoleName = getRandomString(8);

		RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(originalRoleName)
				.clickSaveRole();

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(originalRoleName));

		rolesIndexPage = rolesIndexPage.clickEditLink(originalRoleName)
				.setRoleName(editedRoleName)
				.clickSaveRole();
		
		assertTrue("Role not Edited Correctly.", rolesIndexPage.isNamePresent(editedRoleName));
		assertTrue("Validation message not present.",rolesIndexPage.isEditValidationPresent(editedRoleName));
		
		rolesIndexPage = rolesIndexPage.clickDeleteButton(editedRoleName);

		assertTrue("Validation message not present.",rolesIndexPage.isDeleteValidationPresent(editedRoleName));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(editedRoleName));

	}

    @Test
    public void testCreateRoleValidation() {
        String whiteSpaceName = "     ";

        // Test whitespace
        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(whiteSpaceName)
                .clickSaveRoleInvalid();

        assertTrue("Blank field error didn't show correctly.",
                rolesIndexPage.getNameError().contains("Name is required."));
    }

    @Test
	public void testCreateRoleDuplicateValidation() {
		String roleName1 = "testNameDuplication";
        String roleName2 = "testNameDuplication";

		// Test duplicates
		RolesIndexPage rolesIndexPage = loginPage.login("user", "password").clickOrganizationHeaderLink()
                .clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName1)
				.clickSaveRole()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName2)
				.clickSaveRoleInvalid();

		assertTrue("Duplicate name error did not show correctly.",
				rolesIndexPage.getDupNameError().contains("That name is already taken."));
	}

	@Test
	public void addApplicationOnlyRole(){
		String roleName = "appOnly" + getRandomString(10);
		String userName = getRandomString(10);
		String password = getRandomString(15);
		String teamName = getRandomString(10);
		String appName = getRandomString(10);

        DatabaseUtils.createTeam(teamName);

		TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                 .clickOrganizationHeaderLink()
                 .clickManageRolesLink()
                 .clickCreateRole()
                 .setRoleName(roleName)
                 .setPermissionValue("canManageApplications", true)
                 .clickSaveRole()
                 .clickOrganizationHeaderLink();

        teamIndexPage.clickManageUsersLink()
                 .clickAddUserLink()
                 .enterName(userName)
                 .enterPassword(password)
                 .enterConfirmPassword(password)
                 .toggleGlobalAccess()
                 .chooseRoleForGlobalAccess(roleName)
                 .clickAddNewUserBtn();

		ApplicationDetailPage applicationDetailPage = teamIndexPage.logout()
                .login(userName, password)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

		assertTrue("new role user was not able to add an application",
                applicationDetailPage.getNameText().contains(appName));
	}

	@Test
	public void testSetPermissions() {
		String roleName = getRandomString(10);
		
		RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                assertFalse("Permission was set to yes when it should have been set to no.",
                        rolesIndexPage.getPermissionValue(permission));
            }
		}

		rolesIndexPage = rolesIndexPage.toggleAllPermissions(true)
                .clickSaveRole()
                .clickEditLink(roleName);

		for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                assertTrue("Permission was set to no when it should have been set to yes."
                        , rolesIndexPage.getPermissionValue(permission));
            }
		}
		
		rolesIndexPage = rolesIndexPage.toggleAllPermissions(false)
                .clickSaveRole()
                .clickEditLink(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                assertFalse("Permission was set to yes when it should have been set to no.",
                        rolesIndexPage.getPermissionValue(permission));
            }
		}

		rolesIndexPage = rolesIndexPage.clickSaveRole()
                .clickDeleteButton(roleName)
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .clickSaveRole()
                .clickEditLink(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                assertTrue("Role was not turned on correctly.", rolesIndexPage.getPermissionValue(permission));
            }
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole()
				.clickDeleteButton(roleName);

		assertTrue("Validation message is Present.",rolesIndexPage.isDeleteValidationPresent(roleName));
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(roleName));
	}

	@Test
	public void testDeleteRoleWithUserAttached(){
		String roleName = getRandomString(10);
        String tempUser = getRandomString(8);

		RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink();
		
		rolesIndexPage = rolesIndexPage.clickCreateRole()
				.setRoleName(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                rolesIndexPage = rolesIndexPage.setPermissionValue(permission, true);
            }
		}
		
		rolesIndexPage = rolesIndexPage.clickSaveRole()
                .clickManageUsersLink()
                .clickAddUserLink()
                .enterName(tempUser)
                .enterPassword("TestPassword")
                .enterConfirmPassword("TestPassword")
                .toggleGlobalAccess()
                .chooseRoleForGlobalAccess(roleName)
                .clickModalSubmit()
                .clickManageRolesLink()
                .clickDeleteButton(roleName)
                .clickManageRolesLink();

		assertFalse("Role was not removed.", rolesIndexPage.isNamePresent(roleName));
	}

    @Test
    public void testProtectedPermissionsRemoval() {
        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
                .clickManageRolesLink()
                .clickEditLink("Administrator");

        for (String permission : Role.ALL_PERMISSIONS) {
            if (permission != "enterprise") {
                assertTrue("Admin role did not have all permissions.", rolesIndexPage.getPermissionValue(permission));
            }
        }

        rolesIndexPage.toggleAllPermissions(false)
                .clickSaveRoleInvalid();

        assertTrue("Protected permission was not protected correctly.",
                rolesIndexPage.getEditRoleError().contains("You cannot remove the Manage Users privilege from this role."));
    }
}
