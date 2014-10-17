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

import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;

public abstract class BaseDataTest extends BaseIT{
    protected static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
    protected static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
    protected static final String BUGZILLA_URL = System.getProperty("BUGZILLA_URL");
    protected static final String BUGZILLA_PROJECTNAME = System.getProperty("BUGZILLAPROJECTNAME");

    protected String teamName;
    protected String appName;

    protected String userName;
    protected String roleName;

    protected String testPassword = "TestPassword";

    protected void initializeTeamAndApp() {
        teamName = createTeam();
        appName = createApplication(teamName);
    }

    protected void initializeTeamAndAppWithIBMScan() {
        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
    }

    protected void createRestrictedUser(String permission) {
        if (permission != null) {
            roleName = createRole();
            DatabaseUtils.removePermission(roleName, permission);

            userName = createSpecificRoleUser(roleName);
        } else {
            throw new RuntimeException("Permission required to create a restricted user.");
        }
    }

}
