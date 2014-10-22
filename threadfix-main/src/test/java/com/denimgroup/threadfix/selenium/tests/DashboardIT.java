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
import com.denimgroup.threadfix.selenium.pages.AnalyticsPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class DashboardIT extends BaseDataTest {

    @Before
    public void initialize() {
        initializeTeamAndAppWithIBMScan();
    }

	@Test
	public void dashboardGraphsDisplayTest(){
        DashboardPage dashboardPage = loginPage.defaultLogin();

		assertFalse("6 month vulnerability graph is not displayed", dashboardPage.is6MonthGraphNoDataFound());
		assertFalse("Top 10 vulnerabilities graph is not displayed", dashboardPage.isTop10GraphNoDataFound());
	}

    //TODO when reportSelect is fixed
    @Ignore
    @Test
    public void leftGraphViewMoreLinkTest() {
        String report = "Vulnerability Trending";

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickLeftViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect(report));
    }

    //TODO when reportSelect is fixed
    @Ignore
    @Test
    public void rightGraphViewMoreLinkTest() {
        String report = "Most Vulnerable Applications";

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickRightViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect(report));
    }

    @Test
    public void dashboardRecentUploadsDisplayTest(){
        DashboardPage dashboardPage = loginPage.defaultLogin();

        assertFalse("Recent Scan Uploads are not displayed.", dashboardPage.isRecentUploadsNoScanFound());
    }

    @Test
    public void dashboardRecentCommentsDisplayTest() {
        String commentText = "Test comment.";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(commentText)
                .clickModalSubmit();

        DashboardPage dashboardPage = applicationDetailPage.clickDashboardLink();

        assertTrue("Comments are not displayed on Dashboard Page.", dashboardPage.isCommentDisplayed());
    }
}
