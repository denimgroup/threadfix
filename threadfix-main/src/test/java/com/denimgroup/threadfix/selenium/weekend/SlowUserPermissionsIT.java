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
package com.denimgroup.threadfix.selenium.weekend;

import com.denimgroup.threadfix.WeekendTests;
import com.denimgroup.threadfix.data.entities.Role;
import com.denimgroup.threadfix.selenium.pages.RolesIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseIT;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

@Category(WeekendTests.class)
public class SlowUserPermissionsIT extends BaseIT{

    @Test
    public void protectedPermissionsRemovalTest() {
        RolesIndexPage rolesIndexPage = loginPage.login("user", "password")
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
}
