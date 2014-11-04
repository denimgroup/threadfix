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
import org.openqa.selenium.By;

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

    @Test
    public void leftGraphViewMoreLinkTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickLeftViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect());
    }

    @Test
    public void rightGraphViewMoreLinkTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickRightViewMore();

        assertTrue("Incorrect report shown.", analyticsPage.isReportCorrect());
    }

    @Test
    public void dashboardRecentUploadsDisplayTest(){
        DashboardPage dashboardPage = loginPage.defaultLogin();

        assertFalse("Recent Scan Uploads are not displayed.", dashboardPage.isRecentUploadsNoScanFound());
    }

    @Test
    public void mostVulnerableApplicationTipInformation() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(driver.findElement(By.id(teamName + appName + "CriticalBar")));

        dashboardPage.hover(teamName + appName + "InfoBar");
        assertTrue("The number of Info Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Info: 218"));

        dashboardPage.hover(teamName + appName + "LowBar");
        assertTrue("The number of Low Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Low: 137"));

        dashboardPage.hover(teamName + appName + "MediumBar");
        assertTrue("The number of Medium Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Medium: 112"));

        dashboardPage.hover(teamName + appName + "HighBar");
        assertTrue("The number of High Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("High: 51"));

        dashboardPage.hover(teamName + appName + "CriticalBar");
        assertTrue("The number of Critical Vulnerabilities in report tip was not correct.",
                dashboardPage.isMostVulnerableTipCorrect("Critical: 15"));
    }

    @Test
    public void mostVulnerableApplicationTipModal() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(driver.findElement(By.id(teamName + appName + "CriticalBar")));

        dashboardPage.clickSVGElement(teamName + appName + "InfoBar");

        assertTrue("Team name was not correct.", dashboardPage.isTeamNameCorrectInVulnerabilitySummaryModal(teamName));
        assertTrue("Application name was not correct.", dashboardPage.isApplicationNameCorrectInVulnerabilitySummaryModal(appName));
        assertTrue("Count was not correct.", dashboardPage.isCountCorrectInVulnerabilitySummaryModal("218"));
    }

    @Test
    public void mostVulnerableApplicationDetailNavigation() {
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Burp Suite"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Skipfish"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Mavituna Security Netsparker"));

        DashboardPage dashboardPage = loginPage.defaultLogin();
        dashboardPage.waitForElement(driver.findElement(By.id(teamName + appName + "CriticalBar")));

        dashboardPage.clickSVGElement(teamName + appName + "InfoBar");
        AnalyticsPage analyticsPage = dashboardPage.clickDetails();

        assertTrue("Info filtered results were not correct.", analyticsPage.isVulnerabilityCountCorrect("Info", "218"));

        assertFalse("Low vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Low"));
        assertFalse("Medium vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Medium"));
        assertFalse("High vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("High"));
        assertFalse("Critical vulnerabilities should have been filtered out.", analyticsPage.isSeverityLevelShown("Critical"));
    }

    @Test
    public void dashboardRecentCommentsDisplayTest() {
        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .expandVulnerabilityByType("Critical79")
                .expandCommentSection("Critical790")
                .addComment("Critical790")
                .setComment(getRandomString(12))
                .clickModalSubmit();

        DashboardPage dashboardPage = applicationDetailPage.clickDashboardLink();

        assertTrue("Comments are not displayed on Dashboard Page.", dashboardPage.isCommentDisplayed());
    }
}
