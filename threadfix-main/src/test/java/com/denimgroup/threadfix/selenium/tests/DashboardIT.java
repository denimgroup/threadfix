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

import com.denimgroup.threadfix.selenium.RegressionTest;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.VulnerabilityDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(RegressionTest.class)
public class DashboardIT extends BaseIT {

	@Test
	public void dashboardGraphsDisplayTest(){
        String teamName = "dashboardGraphTestTeam" + getRandomString(3);
        String appName = "dashboardGraphTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.login("user", "password");

		assertFalse("6 month vulnerability graph is not displayed", dashboardPage.is6MonthGraphNoDataFound());
		assertFalse("Top 10 vulnerabilities graph is not displayed", dashboardPage.isTop10GraphNoDataFound());
	}

    @Test
    public void dashboardRecentUploadsDisplayTest(){
        String teamName = "dashboardGraphTestTeam" + getRandomString(3);
        String appName = "dashboardGraphTestApp" + getRandomString(3);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.login("user", "password");

        assertFalse("Recent Scan Uploads are not displayed.", dashboardPage.isRecentUploadsNoScanFound());
    }

    @Test
    public void dashboardRecentCommentsDisplayTest() {
        String teamName = "dashboardGraphTestTeam" + getRandomString(3);
        String appName = "dashboardGraphTestApp" + getRandomString(3);
        String commentText = "This is a test comment.";

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        TeamIndexPage teamIndexPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink();

        ApplicationDetailPage applicationDetailPage = teamIndexPage.expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab();

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickViewScan()
                .clickViewFinding(1)
                .clickViewVulnerability()
                .clickAddComment()
                .setCommentText(commentText)
                .clickSubmitComment();

        DashboardPage dashboardPage = vulnerabilityDetailPage.clickDashboardLink();

        assertTrue("Comments are not displayed on Dashboard Page.", dashboardPage.isCommentDisplayed());
    }

}
