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

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.GroupIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

@Category(EnterpriseTests.class)
public class GroupEntIT extends BaseDataTest {

    private static final String baseUser = "user";
    private static final String baseRole = "User";

    public GroupIndexPage initialize(String groupName) {
        return loginPage.defaultLogin()
                .clickManageGroupsLink()
                .clickCreateGroup()
                .setGroupName(groupName)
                .clickSaveGroup();
    }

    @Test
    public void testCreateGroup() {
        String groupName = getName();

        GroupIndexPage groupIndexPage = initialize(groupName);

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Successfully created new group"));
    }

    @Test
    public void testDeleteGroup() {
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickDeleteButton(groupName);

        assertFalse("Group not removed.", groupIndexPage.isGroupPresent(groupName));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Group was successfully deleted."));
    }

    @Test
    public void testEditGroupName() {
        String originalGroupName = getName();
        String editedGroupName = getName();
        createGroup(originalGroupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(originalGroupName));

        groupIndexPage.clickEditLink(originalGroupName)
                .editGroupName(editedGroupName)
                .clickSaveGroup();

        assertTrue("Group not edited correctly.", groupIndexPage.isGroupPresent(editedGroupName));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Edit succeeded."));
    }

    @Test
    public void testEditGroupGlobalRole() {
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .setGroupGlobalRole(baseRole)
                .clickSaveGroup();

        assertTrue("Global Role was not updated.", groupIndexPage.getGroupGlobalRole().equals(baseRole));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Edit succeeded."));

    }

    @Test
    public void testCreateGroupValidation(){
        String whitespace = "      ";

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink()
                .clickCreateGroup()
                .setGroupName(whitespace);

        assertTrue("Blank field error did not show correctly.",
                groupIndexPage.getNameError().contains("Name is required."));
        assertFalse("Submit Changes button is still selectable", groupIndexPage.isSaveChangesClickable());
    }

    @Test
    public void testEditGroupValidation(){
        String groupName = getName();
        String whitespace = "      ";
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .editGroupName(whitespace);

        assertTrue("Blank field error did not show correctly.",
                groupIndexPage.getEditNameError().contains("Name is required."));
        assertFalse("Submit Changes button is still selectable", groupIndexPage.isSaveChangesClickable());
    }

    @Test
    public void testCreateDuplicateGroupValidation(){
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("First group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickCreateGroup()
                .setGroupName(groupName)
                .clickSaveGroup();

        assertTrue("Duplicate name error did not show correctly.",
                groupIndexPage.getDuplicateNameError().contains("Failure: A group with that name already exists."));
    }

    @Test
    public void testEditDuplicateGroupValidation() {
        String groupName = getName();
        String secondGroupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("First Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickCreateGroup()
                .setGroupName(secondGroupName)
                .clickSaveGroup();

        assertTrue("Second Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(secondGroupName)
                .editGroupName(groupName)
                .clickSaveGroup();

        assertTrue("Duplicate field error did not show correctly.",
                groupIndexPage.getErrorAlertMessage().contains("That name is already taken."));
    }

    @Test
    public void testAddUserToGroup() {
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .setUserField(baseUser)
                .clickAddUser();

        assertTrue("User not added.", groupIndexPage.isUserPresent(baseUser));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("User " + baseUser + " was added."));
    }

    @Test
    public void testRemoveUserFromGroup() {
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .setUserField(baseUser)
                .clickAddUser();

        assertTrue("User not added.", groupIndexPage.isUserPresent(baseUser));

        groupIndexPage.clickRemoveUser(baseUser);

        assertFalse("User not removed.", groupIndexPage.isUserPresent(baseUser));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("User " + baseUser + " was removed."));
    }

    @Test
    public void testAddTeamRoleToGroup() {
        String teamName = createTeam();
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddTeamRole()
                .setTeamName(teamName)
                .setTeamRole(baseRole)
                .clickSaveGroup();

        assertTrue("Team Role not added.", groupIndexPage.isTeamRolePresent(teamName, baseRole));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Successfully added permissions."));
    }

    @Test
    public void testEditTeamRoleFromGroup() {
        String teamName = createTeam();
        String secondTeamName = createTeam();
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddTeamRole()
                .setTeamName(teamName)
                .setTeamRole(baseRole)
                .clickSaveGroup();

        assertTrue("Team Role not added.", groupIndexPage.isTeamRolePresent(teamName, baseRole));

        groupIndexPage.clickEditTeamRole(teamName, baseRole)
                .setTeamName(secondTeamName)
                .setTeamRole("Administrator")
                .clickSaveGroup();

        assertTrue("Team Role not edited.", groupIndexPage.isTeamRolePresent(secondTeamName, "Administrator"));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Successfully edited permissions."));
    }

    @Test
    public void testDeleteTeamRoleFromGroup() {
        String teamName = createTeam();
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddTeamRole()
                .setTeamName(teamName)
                .setTeamRole(baseRole)
                .clickSaveGroup();

        assertTrue("Team Role not added.", groupIndexPage.isTeamRolePresent(teamName, baseRole));

        groupIndexPage.clickDeleteTeamRole(teamName, baseRole);

        assertFalse("Team Role not deleted.", groupIndexPage.isTeamRolePresent(teamName, baseRole));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Permission was successfully deleted."));
    }

    @Test
    public void testAddApplicationRoleToGroup() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddApplicationRole()
                .setTeamName(teamName)
                .setApplicationRole(appName, baseRole)
                .clickSaveGroup();

        assertTrue("Application Role not added.", groupIndexPage.isApplicationRolePresent(teamName, appName, baseRole));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Successfully added permissions."));
    }

    @Test
    public void testEditApplicationRoleFromGroup() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String secondTeamName = createTeam();
        String secondAppName = createApplication(secondTeamName);
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddApplicationRole()
                .setTeamName(teamName)
                .setApplicationRole(appName, baseRole)
                .clickSaveGroup();

        assertTrue("Application Role not added.", groupIndexPage.isApplicationRolePresent(teamName, appName, baseRole));

        groupIndexPage.clickEditApplicationRole(teamName, appName, baseRole)
                .setTeamName(secondTeamName)
                .setApplicationRole(secondAppName, "Administrator")
                .clickSaveGroup();

        assertTrue("Application Role not edited.",
                groupIndexPage.isApplicationRolePresent(secondTeamName, secondAppName, "Administrator"));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Successfully edited permissions."));
    }

    @Test
    public void testDeleteApplicationRoleFromTeam() {
        String teamName = createTeam();
        String appName = createApplication(teamName);
        String groupName = getName();
        createGroup(groupName);

        GroupIndexPage groupIndexPage = loginPage.defaultLogin()
                .clickManageGroupsLink();

        assertTrue("Group not added.", groupIndexPage.isGroupPresent(groupName));

        groupIndexPage.clickEditLink(groupName)
                .clickAddApplicationRole()
                .setTeamName(teamName)
                .setApplicationRole(appName, baseRole)
                .clickSaveGroup();

        assertTrue("Application Role not added.", groupIndexPage.isApplicationRolePresent(teamName, appName, baseRole));

        groupIndexPage.clickDeleteApplicationRole(teamName, appName, baseRole);

        assertFalse("Application Role not deleted.",
                groupIndexPage.isApplicationRolePresent(teamName, appName, "Administrator"));
        assertTrue("Validation message is not present.", groupIndexPage.isValidationPresent());
        assertTrue("Validation message is not correct.",
                groupIndexPage.getValidationMessage().contains("Permission was successfully deleted."));
    }
}
