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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import javax.validation.constraints.AssertTrue;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsSnapshotIT extends BaseDataTest{

    //===========================================================================================================
    // Point in Time Report
    //===========================================================================================================

    @Test
    public void testSnapshotTeamFilter() {
        initializeTeamAndAppWithIbmScan();
        String teamName2 = createTeam();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true);

        analyticsPage.expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        sleep(10000);

        assertTrue("Only 10 high vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("High", "10"));
        assertTrue("Only 8 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter("snapshotFilterDiv")
                .addTeamFilter(teamName2, "snapshotFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testSnapshotApplicationFilter() {
        initializeTeamAndAppWithIbmScan();
        String teamName2 = createTeam();
        String appName2 = createApplication(teamName2);

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(15000);

        analyticsPage.expandTeamApplicationFilter("snapshotFilterDiv")
                .addApplicationFilter(appName, "snapshotFilterDiv")
                .sleepOnArrival(15000);

        //Runtime Fix
        sleep(10000);
        analyticsPage.takeScreenShot();

        assertTrue("Only 10 high vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("High", "10"));
        assertTrue("Only 8 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter("snapshotFilterDiv")
                .addApplicationFilter(appName2, "snapshotFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testExpandCollapseFilters() {
        initializeTeamAndAppWithWebInspectScan();
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true);

        int filtersCollapsedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        analyticsPage.toggleAllFilter("snapshotFilterDiv", true);

        int filtersExpandedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilter("snapshotFilterDiv", false);
        assertFalse("Filters were not collapsed.",
                filtersExpandedSize == analyticsPage.getFilterDivHeight("snapshotFilterDiv"));
    }

    @Test
    public void testChartTipCount() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(15000)
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName,"snapshotFilterDiv");

        //Runtime Fix
        sleep(5000);

        analyticsPage.hoverRealOverSVGElement("pointInTimeInfoArc");
        String numTip = driver.findElement(By.id("pointInTimeTip")).getText().split("\\s+")[1];
        String numBadge = driver.findElement(By.id("totalBadgeInfo")).getText().trim();

        assertTrue("Tip value at level 'Info' does not match badge", numBadge.equals(numTip));
    }

    @Test
    public void testLegendCount() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(15000)
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName,"snapshotFilterDiv");

        //Runtime Fix
        sleep(5000);

        String numLegend = driver.findElement(By.id("legendInfo"))
                .getText().replace("Info", "").split("\\(")[0];
        String numBadge = driver.findElement(By.id("totalBadgeInfo")).getText().trim();

        assertTrue("Legend value at level 'Info' does not match badge", numBadge.equals(numLegend));
    }

    @Test
    public void testClosePieModal() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .sleepOnArrival(15500);

        analyticsPage.clickSVGElement("pointInTimeInfoArc");

        driver.findElement(By.xpath("//*[@id=\"reports\"]/div[8]/div/div/div[4]/button[1]")).click();

        assertTrue("Modal did not close at level Info", analyticsPage.isClickable("reportSnapshotSelect"));
    }

    @Test
    public void testPointInTimeNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        analyticsPage.selectDropDownReport("Point in Time");

        //Runtime Fix
        sleep(10000);

        assertTrue("Did not navigate correctly", driver.findElement(By.id("Point in Time Report_Title"))
                .getText().contains("Point in Time Report"));
    }

    //===========================================================================================================
    // Progress by Vulnerability Report
    //===========================================================================================================

    @Test
    public void testProgressByVulnerabilityNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        analyticsPage.selectDropDownReport("Progress By Vulnerability");

        assertTrue("Did not navigate correctly", driver.findElement(By.id("vulnerabilityProgressByTypeTitle"))
                .getText().equals("Vulnerability Progress By Type"));
    }

    @Test
    public void testVulnerabilityClosedTime() {
        initializeTeamAndAppWithWebInspectScan();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin().clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton();

        AnalyticsPage analyticsPage = applicationDetailPage.clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(10000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        //Runtime Fix
        sleep(10000);

        analyticsPage.clickAverageTimeToCloseSortButton(1);

        assertFalse("Average Time to Close did not show a non-zero close time.",
                ("0").equals(driver.findElement(By.id("averageTimeToCloseVuln0")).getText()));
    }

    @Test
    public void testProgressByVulnerabilityInTimeFieldFilters() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(10000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandFieldControls("snapshotFilterDiv")
                .selectFieldControls("Low", "snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .selectFieldControls("High", "snapshotFilterDiv")
                .selectFieldControls("Critical", "snapshotFilterDiv");

        assertTrue("Info Vulnerability is not present.", analyticsPage.getProgressByVulnerabilityType("0").contains("Information Exposure"));
        assertTrue("Other Vulnerabilities are not filtered out.", analyticsPage.isProgressByVulnerabilityCountCorrect(1));
    }

    @Test
    public void testProgressByVulnerabilityTeamFilterCount() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(10000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        //Runtime Fix
        sleep(15000);
        analyticsPage.takeScreenShot();

        assertTrue("Team specific vulnerabilities are not correct.",
                driver.findElement(By.id("totalVuln0")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln1")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln2")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln3")).getText().equals("2") &&
                        driver.findElement(By.id("totalVuln4")).getText().equals("2") &&
                        driver.findElement(By.id("totalVuln5")).getText().equals("2") &&
                        driver.findElement(By.id("totalVuln6")).getText().equals("2"));
    }

    @Test
    public void testProgressByVulnerabilityCheckSavedFilter() {
        initializeTeamAndAppWithIbmScan();
        initializeTeamAndAppWithWebInspectScan();
        String filterName = getName();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(true)
                .sleepOnArrival(15000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv")
                .saveCurrentFilter(filterName, "snapshotFilterDiv");

        //Runtime Fix
        analyticsPage.refreshPage();

        analyticsPage.clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(15000)
                .selectDropDownReport("Progress By Vulnerability")
                .loadFilter(filterName,"snapshotFilterDiv");

        //Runtime Fix
        sleep(15000);

        assertTrue("Team specific vulnerabilities are not correct.",
                driver.findElement(By.id("totalVuln0")).getText().equals("1") &&
                    driver.findElement(By.id("totalVuln1")).getText().equals("1") &&
                    driver.findElement(By.id("totalVuln2")).getText().equals("1") &&
                    driver.findElement(By.id("totalVuln3")).getText().equals("2") &&
                    driver.findElement(By.id("totalVuln4")).getText().equals("2") &&
                    driver.findElement(By.id("totalVuln5")).getText().equals("2") &&
                    driver.findElement(By.id("totalVuln6")).getText().equals("2"));
    }

    //===========================================================================================================
    // Most Vulnerable Applications Report
    //===========================================================================================================

    @Test
    public void testMostVulnerableAppGraphTips() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        assertTrue("Tip at level info does not match count", analyticsPage.mostVulnAppTip("Info", teamName, appName)
                .equals("Info: 17"));
        assertTrue("Tip at level low does not match count", analyticsPage.mostVulnAppTip("Low",teamName,appName)
                .equals("Low: 139"));
        assertTrue("Tip at level medium does not match count", analyticsPage.mostVulnAppTip("Medium",teamName,appName)
                .equals("Medium: 117"));
        assertTrue("Tip at level high does not match count", analyticsPage.mostVulnAppTip("High",teamName,appName)
                .equals("High: 37"));
        assertTrue("Tip at level critical does not match count", analyticsPage.mostVulnAppTip("Critical",teamName,appName)
                .equals("Critical: 27"));
    }

    @Test
    public void testMostVulnerableAppModalHeader() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        assertTrue("Tip at level info does not match count", analyticsPage.mostVulnAppModalHeader("Info", teamName, appName)
                .equals("Info: 17"));
    }

    @Test
    public void testMostVulnerableAppsNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        //Runtime Fix
        sleep(5000);

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        //Runtime Fix
        sleep(10000);

        assertTrue("Did not navigate correctly", driver.findElement(By.id("Most Vulnerable Applications_Title"))
                .getText().equals("Most Vulnerable Applications"));
    }

    @Test
    public void testMostVulnerableAppTestFilter() {
        initializeTeamAndAppWithWebInspectScan();

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .expandFieldControls("snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        assertTrue("Info Bar is not present", !driver.findElements(By.id(teamName + appName + "InfoBar")).isEmpty());
        assertTrue("Low Bar is not present", !driver.findElements(By.id(teamName + appName + "LowBar")).isEmpty());
        assertTrue("Medium Bar shouldn't be present", driver.findElement(By.id(teamName + appName + "MediumBar"))
                .getAttribute("width") == null);
        assertTrue("High Bar is not present", !driver.findElements(By.id(teamName + appName + "HighBar")).isEmpty());
        assertTrue("Critical Bar is not present", !driver.findElements(By.id(teamName + appName + "CriticalBar")).isEmpty());
    }

    @Test
    public void testMostVulnerableAppSaveFilter() {
        initializeTeamAndAppWithWebInspectScan();
        String filterName = getName();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .expandFieldControls("snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv")
                .saveCurrentFilter(filterName, "snapshotFilterDiv");

        analyticsPage.clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(true)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .loadFilter(filterName, "snapshotFilterDiv");

        assertTrue("Medium Bar shouldn't be present", driver.findElement(By.id(teamName + appName + "MediumBar"))
                .getAttribute("width") == null);
    }

    //===========================================================================================================
    // OWASP Top 10 Report
    //===========================================================================================================

    @Test
    public void testOwaspReportFilterByYear() {
        initializeTeamAndAppWithAppScanEnterpriseScan();
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("OWASP Top 10")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        String[] owaspThirteen = {"13", "3", "9", "0", "11", "3", "0", "6", "0", "1"};
        String[] owaspTen = {"10", "9", "0", "0", "6", "11", "3", "0", "2", "1"};
        String[] owaspSeven = {"9", "13", "0", "0", "6", "14", "5", "2", "2", "0"};

        for(int index = 0; index < 10; index++) {
            assertTrue("OWASP 2013: A" + (index + 1) + " did not contain correct number of vulnerabilities",
                    analyticsPage.isOwaspCountCorrect(Integer.toString(index + 1), owaspThirteen[index]));
        }

        analyticsPage.expandOwaspTopTenFilter("snapshotFilterDiv")
                .selectOwaspYear("2010", "snapshotFilterDiv")
                .waitForResultsToLoad();

        for(int index = 0; index < 10; index++) {
            assertTrue("OWASP 2010: A" + (index + 1) + " did not contain correct number of vulnerabilities",
                    analyticsPage.isOwaspCountCorrect(Integer.toString(index + 1), owaspTen[index]));
        }

        analyticsPage.selectOwaspYear("2007", "snapshotFilterDiv")
                .waitForResultsToLoad();

        for(int index = 0; index < 10; index++) {
            assertTrue("OWASP 2007: A" + (index + 1) + " did not contain correct number of vulnerabilities",
                    analyticsPage.isOwaspCountCorrect(Integer.toString(index + 1), owaspSeven[index]));
        }
    }

    //===========================================================================================================
    // Portfolio Report
    //===========================================================================================================

    @Test
    public void testPortfolioReportSummary() {
        initializeTeamAndAppWithIbmScan();
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Portfolio");

        assertTrue("Default Team filter is incorrect.", analyticsPage.getPortfolioSummaryItem(1).equals("All"));
        assertTrue("Default Application filter is incorrect.", analyticsPage.getPortfolioSummaryItem(2).equals("All"));
        assertTrue("Default Tag filter is incorrect.", analyticsPage.getPortfolioSummaryItem(3).equals("All"));

        analyticsPage.expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        assertTrue("Team filter is incorrect.", analyticsPage.getPortfolioSummaryItem(1).equals(teamName));
        assertTrue("Application filter is incorrect.",analyticsPage.getPortfolioSummaryItem(2).equals(""));
        assertTrue("Number of Applications is incorrect.", analyticsPage.getPortfolioSummaryItem(4).equals("1"));
        assertTrue("Number of Scans is incorrect.", analyticsPage.getPortfolioSummaryItem(5).equals("1"));

        analyticsPage.addApplicationFilter(appName, "snapshotFilterDiv");

        assertTrue("Team filter is incorrect.", analyticsPage.getPortfolioSummaryItem(1).equals(teamName));
        assertTrue("Application filter is incorrect.",
                analyticsPage.getPortfolioSummaryItem(2).equals(teamName + " / " + appName));
        assertTrue("Number of Applications is incorrect.", analyticsPage.getPortfolioSummaryItem(4).equals("1"));
        assertTrue("Number of Scans is incorrect.", analyticsPage.getPortfolioSummaryItem(5).equals("1"));
    }

    //===========================================================================================================
    // DISA STIG
    //===========================================================================================================

    @Test
    public void testDisaStigReportDisplaysBasicElements() {
        initializeTeamAndAppWithWebInspectScan();
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("DISA STIG")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        //Runtime Fix
        sleep(5000);

        assertTrue("CAT I node did not contain correct number of vulnerabilities.",
                analyticsPage.isVulnerabilityCountCorrect("CAT I", "1"));
        assertTrue("CAT II node did not contain correct number of vulnerabilities.",
                analyticsPage.isVulnerabilityCountCorrect("CAT II", "15"));
        assertTrue("CAT III node did not contain correct number of vulnerabilities.",
                analyticsPage.isVulnerabilityCountCorrect("CAT III", "0"));

    }

    //===========================================================================================================
    // Scan Comparison Summary
    //===========================================================================================================

    @Test
    public void testScanComparisonSummary() {
        initializeTeamAndApp();
        String repositoryURL = "https://github.com/spring-projects/spring-petclinic.git";
        String scannerName = "IBM Rational AppScan";

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickEditDeleteBtn()
                .expandSourceCodeFields()
                .setRepositoryURLEdited(repositoryURL)
                .clickModalSubmit();

        uploadScanToApp(teamName, appName, "Petclinic XML");

        VulnerabilityDetailPage vulnerabilityDetailPage = applicationDetailPage.clickScansHeaderLink()
                .clickViewScanLink()
                .clickViewFinding()
                .clickViewVulnerability()
                .clickMarkasFalsePositivebutton();

        AnalyticsPage analyticsPage = vulnerabilityDetailPage.clickAnalyticsLink()
                .waitForReportTab("snapshot")
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Scan Comparison Summary")
                .expandTeamApplicationFilter("snapshotFilterDiv")
                .addTeamFilter(teamName, "snapshotFilterDiv");

        assertTrue("Total Vulnerabilities is incorrect.", analyticsPage.getScanComparisonSummaryItem(5).equals("39"));

        assertTrue("Number Found is incorrect.", analyticsPage.getScanComparisonFoundCount("0").equals("39"));
        assertTrue("Percent Found is incorrect.", analyticsPage.getScanComparisonFoundPercent("0").equals("100%"));
        assertTrue("Number of False Positives is incorrect.",
                analyticsPage.getScanComparisonFalsePostiveCount("0").equals("1"));
        assertTrue("Percent of False Positives is incorrect.",
                analyticsPage.getScanComparisonFalsePositivePercent("0").equals("2.6%"));
        assertTrue("Found HAM Endpoint number is incorrect.",
                analyticsPage.getScanComparisonHAMEndpointCount("0").equals("26"));
        assertTrue("Found HAM Endpoint percent is incorrect.",
                analyticsPage.getScanComparisonHAMEndpointPercent("0").equals("66.7%"));
    }
}
