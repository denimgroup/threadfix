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
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsSnapshotIT extends BaseDataTest{

    @Test
    public void snapshotD3TeamFilterTest() {
        initializeTeamAndAppWithIBMScan();
        String teamName2 = createTeam();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(false);

        analyticsPage.expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        analyticsPage.waitForElement(driver.findElement(By.id("totalBadgeCritical")));

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName2, "snapshotFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void snapshotD3ApplicationFilterTest() {
        initializeTeamAndAppWithIBMScan();
        String teamName2 = createTeam();
        String appName2 = createApplication(teamName2);

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(false);

        analyticsPage.expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addApplicationFilterReport(appName, "snapshotFilterDiv");

        analyticsPage.waitForElement(driver.findElement(By.id("totalBadgeCritical")));

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilterReport("snapshotFilterDiv")
                .addApplicationFilterReport(appName2, "snapshotFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void expandCollapseTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        int filtersCollapsedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        analyticsPage.toggleAllFilterReport("snapshotFilterDiv", true);

        int filtersExpandedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilterReport("snapshotFilterDiv", false);
        assertFalse("Filters were not collapsed.",
                filtersExpandedSize == analyticsPage.getFilterDivHeight("snapshotFilterDiv"));
    }

    @Test
    public void testTipCount() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(15000)
                .clickSnapshotTab(true)
                .sleepOnArrival(15000)
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName,"snapshotFilterDiv");

        for(int i = 0; i < 5; i++) {
            analyticsPage.hoverRealOverSVGElement("pointInTime" + levels[i] + "Arc");
            String numTip = driver.findElement(By.id("pointInTimeTip")).getText().split("\\s+")[1];
            String numBadge = driver.findElement(By.id("totalBadge" + levels[i])).getText().trim();

            assertTrue("Tip value at level " + levels[i] + " does not match badge", numBadge.equals(numTip));
        }
    }

    @Test
    public void testLegendCount() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(15000)
                .clickSnapshotTab(false)
                .sleepOnArrival(15000)
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName,"snapshotFilterDiv");

        for(int i = 0; i < 5; i++) {
            String numLegend = driver.findElement(By.id("legend" + levels[i]))
                    .getText().replace(levels[i], "").split("\\(")[0];
            String numBadge = driver.findElement(By.id("totalBadge" + levels[i])).getText().trim();

            assertTrue("Legend value at level " + levels[i] + " does not match badge", numBadge.equals(numLegend));
        }
    }

    @Test
    public void pieModalCloseTest() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        String[] levels = {"Info","Low","Medium","High","Critical"};

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        for(int i = 0; i < 5; i++) {
            sleep(2500);

            analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc");

            driver.findElement(By.xpath("//*[@id=\"reports\"]/div[8]/div/div/div[4]/button[1]")).click();

            assertTrue("Modal did not close at level " + levels[i], analyticsPage.isClickable("reportSnapshotSelect"));
        }
    }

    @Test
    public void checkMostVulnerableAppTips() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        assertTrue("Tip at level info does not match count", analyticsPage.mostVulnAppTip("Info", teamName, appName)
                .equals("Info: 120"));
        assertTrue("Tip at level low does not match count", analyticsPage.mostVulnAppTip("Low",teamName,appName)
                .equals("Low: 139"));
        assertTrue("Tip at level medium does not match count", analyticsPage.mostVulnAppTip("Medium",teamName,appName)
                .equals("Medium: 115"));
        assertTrue("Tip at level high does not match count", analyticsPage.mostVulnAppTip("High",teamName,appName)
                .equals("High: 38"));
        assertTrue("Tip at level critical does not match count", analyticsPage.mostVulnAppTip("Critical",teamName,appName)
                .equals("Critical: 27"));
    }

    @Test
    public void checkMostVulnerableAppModalHeader() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true)
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        assertTrue("Tip at level info does not match count", analyticsPage.mostVulnAppModalHeader("Info", teamName, appName)
                .equals("Info: 120"));
    }

    @Test
    public void checkProgressByVulnNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        analyticsPage.selectDropDownReport("Progress By Vulnerability");

        assertTrue("Did not navigate correctly", driver.findElement(By.id("vulnerabilityProgressByTypeTitle"))
                .getText().equals("Vulnerability Progress By Type"));
    }

    @Test
    public void checkMostVulnAppsNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        analyticsPage.selectDropDownReport("Most Vulnerable Applications");

        assertTrue("Did not navigate correctly", driver.findElement(By.id("Most Vulnerable Applications_Title"))
                .getText().equals("Most Vulnerable Applications"));
    }

    @Test
    public void checkPointInTimeNav() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab(true);

        analyticsPage.selectDropDownReport("Most Vulnerable Applications")
                .selectDropDownReport("Point in Time");

        assertTrue("Did not navigate correctly", driver.findElement(By.id("Point in Time Report_Title"))
                .getText().equals("Point in Time Report"));
    }

    @Test
    public void checkVulnClosedTime() {
        initializeTeamAndAppWithWebInspectScan();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin().clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName);

        applicationDetailPage.expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton();

        AnalyticsPage analyticsPage = applicationDetailPage.clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        analyticsPage.waitForElement(driver.findElement(By.id("averageTimeToCloseVuln5")));

        assertTrue("Time to close is invalid.",
                Integer.parseInt(driver.findElement(By.id("averageTimeToCloseVuln5")).getText()) >= 0);
    }

    @Test
    public void progressByVulnInTimeFieldFilters() {
        initializeTeamAndAppWithWebInspectScan();

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandFieldControlsReport("snapshotFilterDiv")
                .selectFieldControls("Info", "snapshotFilterDiv")
                .selectFieldControls("Low", "snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .selectFieldControls("High", "snapshotFilterDiv")
                .selectFieldControls("Critical", "snapshotFilterDiv");

        assertTrue("Field controls did not work.", driver.findElements(By.id("averageTimeToCloseVuln5")).isEmpty());
    }

    @Test
    public void progressByVulnTeamFilterCount() {
        initializeTeamAndAppWithWebInspectScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        analyticsPage.waitForElement(driver.findElement(By.id("totalVuln0")));

        assertTrue("Team specific vulnerabilities are not correct.",
                driver.findElement(By.id("totalVuln0")).getText().equals("1") &&
                driver.findElement(By.id("totalVuln1")).getText().equals("1") &&
                driver.findElement(By.id("totalVuln2")).getText().equals("1") &&
                driver.findElement(By.id("totalVuln3")).getText().equals("1") &&
                driver.findElement(By.id("totalVuln4")).getText().equals("2") &&
                driver.findElement(By.id("totalVuln5")).getText().equals("3") &&
                driver.findElement(By.id("totalVuln6")).getText().equals("18"));
    }

    @Test
    public void progressByVulnCheckSavedFilter() {
        initializeTeamAndAppWithIBMScan();
        initializeTeamAndAppWithWebInspectScan();
        String filterName = getName();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Progress By Vulnerability")
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv")
                .saveCurrentFilterReport(filterName, "snapshotFilterDiv");

        analyticsPage.clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Progress By Vulnerability")
                .loadFilterReport(filterName,"snapshotFilterDiv");

        analyticsPage.waitForElement(driver.findElement(By.id("totalVuln0")));

        assertTrue("Team specific vulnerabilities are not correct.",
                driver.findElement(By.id("totalVuln0")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln1")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln2")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln3")).getText().equals("1") &&
                        driver.findElement(By.id("totalVuln4")).getText().equals("2") &&
                        driver.findElement(By.id("totalVuln5")).getText().equals("3") &&
                        driver.findElement(By.id("totalVuln6")).getText().equals("18"));
    }

    @Test
    public void mostVulnAppTestFilter() {
        initializeTeamAndAppWithWebInspectScan();

        loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .expandFieldControlsReport("snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv");

        assertTrue("Info Bar is not present", !driver.findElements(By.id(teamName + appName + "InfoBar")).isEmpty());
        assertTrue("Low Bar is not present", !driver.findElements(By.id(teamName + appName + "LowBar")).isEmpty());
        assertTrue("Medium Bar shouldn't be present", driver.findElement(By.id(teamName + appName + "MediumBar"))
                .getAttribute("width").equals("0"));
        assertTrue("High Bar is not present", !driver.findElements(By.id(teamName + appName + "HighBar")).isEmpty());
        assertTrue("Critical Bar is not present", !driver.findElements(By.id(teamName + appName + "CriticalBar")).isEmpty());
    }

    @Test
    public void mostVulnAppSaveFilter() {
        initializeTeamAndAppWithWebInspectScan();
        String filterName = getName();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(false)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .expandFieldControlsReport("snapshotFilterDiv")
                .selectFieldControls("Medium", "snapshotFilterDiv")
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName, "snapshotFilterDiv")
                .saveCurrentFilterReport(filterName, "snapshotFilterDiv");

        analyticsPage.clickAnalyticsLink()
                .sleepOnArrival(5000)
                .clickSnapshotTab(true)
                .sleepOnArrival(5000)
                .selectDropDownReport("Most Vulnerable Applications")
                .loadFilterReport(filterName, "snapshotFilterDiv");

        assertTrue("Medium Bar shouldn't be present", driver.findElement(By.id(teamName + appName + "MediumBar"))
                .getAttribute("width").equals("0"));
    }
}
