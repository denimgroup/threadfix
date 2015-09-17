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
package com.denimgroup.threadfix.selenium.weekend;

import com.denimgroup.threadfix.WeekendTests;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(WeekendTests.class)
public class SlowUserPermissionsIT extends BaseIT{

    private static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
    private static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
    private static final String BUGZILLA_URL = System.getProperty("BUGZILLA_URL");

    @Test
    public void protectedPermissionsRemovalTest() {
        RolesIndexPage rolesIndexPage = loginPage.defaultLogin()
                .clickManageRolesLink()
                .clickEditLink("Administrator");

        for (String permission : Role.ALL_PERMISSIONS) {
            if (!permission.equals("enterprise")) {
                assertTrue("Admin role did not have all permissions.", rolesIndexPage.getPermissionValue(permission));
            }
        }

        rolesIndexPage.toggleAllPermissions(false)
                .clickSaveRoleInvalid();

        assertTrue("Protected permission was not protected correctly.",
                rolesIndexPage.getEditRoleError().contains("You cannot remove the Manage Users privilege from this role."));
    }

    @Test
    public void checkDefectTrackerPermission() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String roleName = getRandomString(8);
        String userName = getRandomString(8);
        String defectTrackerName = "testCreateDefectTracker"+ getRandomString(3);
        String defectTrackerType = "Bugzilla";

        DefectTrackerIndexPage defectTrackerIndexPage = loginPage.defaultLogin()
                .clickDefectTrackersLink()
                .clickAddDefectTrackerButton()
                .setName(defectTrackerName)
                .setURL(BUGZILLA_URL)
                .setType(defectTrackerType)
                .clickSaveDefectTracker();

        RolesIndexPage rolesIndexPage = defectTrackerIndexPage.clickManageRolesLink()
                .clickCreateRole()
                .setRoleName(roleName)
                .toggleAllPermissions(true)
                .toggleSpecificPermission(false,"canManageDefectTrackers")
                .clickSaveRole();

        UserIndexPage userIndexPage = rolesIndexPage.clickManageUsersLink()
                .clickCreateUserButton()
                .setName(userName)
                .setPassword("TestPassword")
                .setConfirmPasswordModal("TestPassword")
                .clickAddNewUserBtn()
                .clickUserLink(userName)
                .chooseRoleForGlobalAccess(roleName)
                .clickSaveChanges();

        LoginPage loginPage = userIndexPage.clickLogOut();

        ApplicationDetailPage applicationDetailPage = loginPage.login(userName, "TestPassword")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickAddDefectTrackerButton()
                .clickCreateNewDefectTracker();

        assertTrue("Was able to begin creating a new Defect Tracker without permission.",
                applicationDetailPage.isCreateDefectTrackerPresent());


        applicationDetailPage.clickCloseModalButton()
                .clickEditDeleteBtn()
                .clickAddDefectTrackerButton()
                .selectDefectTracker(defectTrackerName)
                .setUsername(BUGZILLA_USERNAME)
                .setPassword(BUGZILLA_PASSWORD)
                .clickTestConnection()
                .selectProduct("QA Testing")
                .clickUpdateApplicationButton();

        assertTrue("Defect Tracker Link is Not Available", applicationDetailPage.isDefectTrackerNameLinkDisplay());

        applicationDetailPage.clickUpdateApplicationButton()
                .clickConfigTab();

        assertFalse("Defect Tracker Link is Present", applicationDetailPage.isDefectTrackerAddPresent());
    }
}
