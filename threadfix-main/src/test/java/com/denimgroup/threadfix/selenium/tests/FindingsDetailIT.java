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

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

/**
 * Created by mghanizadeh on 9/3/2014.
 */

@Category(CommunityTests.class)
public class FindingsDetailIT extends BaseIT{
    private String teamName;
    private String appName;

    @Before
    public void initialize() {
        teamName = getRandomString(8);
        appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
    }

    @Test
    public void vulnerabilityNavigationTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab();
        ScanDetailPage scanDetailPage = applicationDetailPage.clickViewScan();

        FindingDetailPage findingDetailPage = scanDetailPage.clickViewFinding();

        VulnerabilityDetailPage vulnerabilityDetailPage = findingDetailPage.clickViewVulnerability();

        assertTrue("Vulnerability Details Page is not Available",
                vulnerabilityDetailPage.isToggleMoreInfoButtonAvailable());
    }

    @Test
    public void checkMergeWithOtherFindingsButton() {
        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab();
        ScanDetailPage scanDetailPage = applicationDetailPage.clickViewScan();

        FindingDetailPage findingDetailPage = scanDetailPage.clickViewFinding();

        MergeFindingPage mergeFindingPage = findingDetailPage.clickMergeWithOtherFindings();

        assertTrue("Vulnerability Details Page is not Available",
                mergeFindingPage.isMergeFindingPagePresent());
    }
}
