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

package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.AnalyticsPage;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class DashboardIT extends BaseDataTest {

    @Before
    public void initialize() {
        initializeTeamAndAppWithIbmScan();
    }

    //===========================================================================================================
    // General Graph Tests
    //===========================================================================================================

	@Test
	public void testDashboardGraphsArePresent(){
        DashboardPage dashboardPage = loginPage.defaultLogin();

		assertFalse("6 month vulnerability graph is not displayed", dashboardPage.is6MonthGraphNoDataFound());
		assertFalse("Top 10 vulnerabilities graph is not displayed", dashboardPage.isTop10GraphNoDataFound());
	}

    @Test
    public void testLeftGraphViewMoreLink() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickLeftViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect());
    }

    @Test
    public void testRightGraphViewMoreLink() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickRightViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect());
    }

    //===========================================================================================================
    // Most Vulnerable Applications Graph
    //===========================================================================================================

    @Test
    public void testMostVulnerableApplicationGraphTips() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(By.id(teamName + appName + "CriticalBar"));

        dashboardPage.hover(teamName + appName + "InfoBar");
        assertTrue("The number of Info Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Info: 167"));

        dashboardPage.hover(teamName + appName + "LowBar");
        assertTrue("The number of Low Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Low: 120"));

        dashboardPage.hover(teamName + appName + "MediumBar");
        assertTrue("The number of Medium Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Medium: 52"));

        dashboardPage.hover(teamName + appName + "HighBar");
        assertTrue("The number of High Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("High: 26"));

        dashboardPage.hover(teamName + appName + "CriticalBar");
        assertTrue("The number of Critical Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Critical: 5"));
    }

    @Test
    public void testMostVulnerableApplicationGraphModal() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(By.id(teamName + appName + "CriticalBar"));

        dashboardPage.clickSVGElement(teamName + appName + "InfoBar");

        assertTrue("Team name was not correct.", dashboardPage.isTeamNameCorrectInVulnerabilitySummaryModal(teamName));
        assertTrue("Application name was not correct.", dashboardPage.isApplicationNameCorrectInVulnerabilitySummaryModal(appName));
        assertTrue("Count was not correct.", dashboardPage.isCountCorrectInVulnerabilitySummaryModal("167"));
    }

    @Test
    public void testMostVulnerableApplicationDetailNavigation() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(By.id(teamName + appName + "CriticalBar"));

        dashboardPage.clickSVGElement(teamName + appName + "InfoBar");
        AnalyticsPage analyticsPage = dashboardPage.clickDetails();

        assertTrue("Info filtered results were not correct.", analyticsPage.isVulnerabilityCountCorrect("Info", "167"));

        assertFalse("Low vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Low"));
        assertFalse("Medium vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Medium"));
        assertFalse("High vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("High"));
        assertFalse("Critical vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Critical"));
    }

    //===========================================================================================================
    // Recent Comments
    //===========================================================================================================

    @Test
    public void testDashboardRecentCommentsElement() {
        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .expandVulnerabilityByType("High79")
                .expandCommentSection("High790")
                .clickAddComment("High790")
                .setComment(getRandomString(12))
                .clickModalSubmit();

        DashboardPage dashboardPage = applicationDetailPage.clickDashboardLink();

        assertTrue("Comments are not displayed on Dashboard Page.", dashboardPage.isCommentDisplayed());
    }

    //===========================================================================================================
    // Recent Uploads
    //===========================================================================================================
    @Test
    public void testRecentUploadsDisplay(){
        DashboardPage dashboardPage = loginPage.defaultLogin();

        assertFalse("Recent Scan Uploads are not displayed.", dashboardPage.isRecentUploadsNoScanFound());
        assertTrue("Most recent upload date is incorrect.",
                dashboardPage.getMostRecentUploadDate().equals("12/01/14"));
        assertTrue("Most recent upload application is incorrect", dashboardPage.getMostRecentUploadApp().equals(appName));
        assertTrue("Most recent upload results are incorrect.",
                dashboardPage.getMostRecentUploadName().contains("44 Vulnerabilities from IBM Security AppScan Standard (Dynamic)"));
    }
}
