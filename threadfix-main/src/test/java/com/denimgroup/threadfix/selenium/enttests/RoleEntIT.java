////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(EnterpriseTests.class)
public class RoleEntIT extends BaseDataTest {

	@Test
	public void testCreateRole() {
        String roleName = getName();

		RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName)
				.clickSaveRole();

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(roleName));
		assertTrue("Validation message is not Present.",rolesIndexPage.isValidationPresent());
	}

    @Test
    public void testDeleteRole() {
        String roleName = getName();

        RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .clickSaveRole();

        assertTrue("Role not added.", rolesIndexPage.isNamePresent(roleName));

        rolesIndexPage = rolesIndexPage.clickDeleteButton(roleName);

        assertTrue("Validation message is not Present.",rolesIndexPage.isValidationPresent());
        assertFalse("Role not removed.", rolesIndexPage.isNamePresent(roleName));
    }

	@Test
	public void testEditRole() {
		String originalRoleName = getName();
		String editedRoleName = getName();

		RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(originalRoleName)
				.clickSaveRole();

		assertTrue("Role not added.", rolesIndexPage.isNamePresent(originalRoleName));

		rolesIndexPage = rolesIndexPage.clickEditLink(originalRoleName)
				.setRoleName(editedRoleName)
				.clickSaveRole();
		
		assertTrue("Role not Edited Correctly.", rolesIndexPage.isNamePresent(editedRoleName));
		assertTrue("Validation message not present.",rolesIndexPage.isValidationPresent());
		
		rolesIndexPage = rolesIndexPage.clickDeleteButton(editedRoleName);

		assertTrue("Validation message not present.",rolesIndexPage.isValidationPresent());
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(editedRoleName));

	}

    @Test
    public void testCreateRoleValidation() {
        String whiteSpaceName = "     ";

        RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(whiteSpaceName)
                .clickSaveRoleInvalid();

        assertTrue("Blank field error didn't show correctly.",
                rolesIndexPage.getNameError().contains("Name is required."));
    }

    @Test
    public void testEditRoleValidation() {
        String roleName = getName();
        String whiteSpaceName = "     ";
        String emptyStringName = "";

        RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .clickSaveRole();

        rolesIndexPage = rolesIndexPage.clickEditLink(roleName)
                .setRoleName(whiteSpaceName);

        assertTrue("White space name error name not shown.",
                rolesIndexPage.getNameError().contains("Name is required."));

        rolesIndexPage.setRoleName(emptyStringName);

        assertTrue("Empty string name error name not shown.",
                rolesIndexPage.getNameError().contains("Name is required."));
    }

    @Test
	public void testCreateRoleDuplicateValidation() {
		String roleName = createRole();

		RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName)
				.clickSaveRoleInvalid();

		assertTrue("Duplicate name error did not show correctly.",
				rolesIndexPage.getDupNameError().contains("That name is already taken."));
	}

	@Test
	public void testAddApplicationOnlyRole(){
		String roleName = createSpecificPermissionRole("canManageApplications");
		String userName = createSpecificRoleUser(roleName);
		initializeTeamAndApp();
        String appName = getName();

		ApplicationDetailPage applicationDetailPage = loginPage.login(userName, testPassword)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

		assertTrue("New role user was not able to add an application",
                applicationDetailPage.getNameText().contains(appName));
	}

	@Test
	public void testSetPermissions() {
		String roleName = getName();
		
		RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
				.clickManageRolesLink()
				.clickCreateRole()
				.setRoleName(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (!permission.equals("enterprise") && !permission.equals("readAccess")) {
                assertFalse("Permission " + permission + " was set to yes when it should have been set to no.",
                        rolesIndexPage.getPermissionValue(permission));
            }
		}

		rolesIndexPage = rolesIndexPage.toggleAllPermissions(true)
                .clickSaveRole(roleName)
                .clickManageRolesLink()
                .clickEditLink(roleName);

		for (String permission : Role.ALL_PERMISSIONS) {
            if (!permission.equals("enterprise") && !permission.equals("readAccess")) {
                assertTrue("Permission " + permission + " was set to no when it should have been set to yes."
                        , rolesIndexPage.getPermissionValue(permission));
            }
		}
		
		rolesIndexPage = rolesIndexPage.toggleAllPermissions(false)
                .clickSaveRole(roleName)
                .clickManageRolesLink()
                .clickEditLink(roleName);
		
		for (String permission : Role.ALL_PERMISSIONS) {
            if (!permission.equals("enterprise") && !permission.equals("readAccess")) {
                assertFalse("Permission " + permission + " was set to yes when it should have been set to no.",
                        rolesIndexPage.getPermissionValue(permission));
            }
		}

		rolesIndexPage = rolesIndexPage.clickSaveRole(roleName)
                .clickManageRolesLink()
				.clickDeleteButton(roleName);

		assertTrue("Validation message is not Present.",rolesIndexPage.isValidationPresent());
		assertFalse("Role not removed.", rolesIndexPage.isNamePresent(roleName));
	}

	@Test
	public void testDeleteRoleWithUserAttached(){
		String roleName = createRole();
        String roleUser = createSpecificRoleUser(roleName);

		RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickDeleteButton(roleName)
                .clickManageRolesLink();

        assertTrue("Validation message is not Present.",rolesIndexPage.isValidationPresent());
		assertFalse("Role was not removed.", rolesIndexPage.isNamePresent(roleName));
	}
}
