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
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsSnapshotIT extends BaseDataTest{

    @Test
    public void pieD3WedgeNavigation() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink();

        for(int i = 0; i < 5; i++) {
            analyticsPage.clickSnapshotTab();

            analyticsPage.waitForElement(driver.findElement(By.id("pointInTime" + levels[i] + "Arc")));

            analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc")
                    .clickModalSubmit();

            assertTrue("Navigation @ level " + levels[i] + " failed", analyticsPage.checkCorrectFilterLevel(levels[i]));
        }
    }

    @Test
    public void snapshotD3TeamFilterTest() {
        initializeTeamAndAppWithIBMScan();
        String teamName2 = createTeam();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab();

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
                .clickSnapshotTab();

        analyticsPage.expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addApplicationFilterReport(appName,"snapshotFilterDiv");

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
                .addApplicationFilterReport(appName2,"snapshotFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void expandCollapseTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickSnapshotTab();

        int filtersCollapsedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        analyticsPage.toggleAllFilterReport("snapshotFilterDiv");

        int filtersExpandedSize = analyticsPage.getFilterDivHeight("snapshotFilterDiv");
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilterReport("snapshotFilterDiv");
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
                .clickSnapshotTab()
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName,"snapshotFilterDiv");

        for(int i = 0; i < 5; i++) {
            analyticsPage.hoverOverSVGElement("pointInTime" + levels[i] + "Arc");
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
                .clickSnapshotTab()
                .expandTeamApplicationFilterReport("snapshotFilterDiv")
                .addTeamFilterReport(teamName,"snapshotFilterDiv");

        for(int i = 0; i < 5; i++) {
            String numLegend = driver.findElement(By.id("legend" + levels[i]))
                    .getText().replace(levels[i],"").split("\\(")[0];
            String numBadge = driver.findElement(By.id("totalBadge" + levels[i])).getText().trim();

            assertTrue("Legend value at level " + levels[i] + " does not match badge", numBadge.equals(numLegend));
        }
    }

    @Test
    public void pieModalNumCheck() {
       initializeTeamAndAppWithWebInspectScan();
       DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
       DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

       String[] levels = {"Info","Low","Medium","High","Critical"};

       AnalyticsPage analyticsPage = loginPage.defaultLogin()
               .clickAnalyticsLink();

       for(int i = 0; i < 5; i++) {
           analyticsPage.clickSnapshotTab()
                   .expandTeamApplicationFilterReport("snapshotFilterDiv")
                   .addTeamFilterReport(teamName,"snapshotFilterDiv");

           sleep(2500);

           analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc");

           String numModal = driver.findElement(By.id("header0")).getText().split("\\s+")[1].trim();
           String numBadge = driver.findElement(By.id("totalBadge" + levels[i])).getText().trim();

           assertTrue("Modal total at level " + levels[i] + " does not match badge",
                   numBadge.equals(numModal));

           analyticsPage.clickModalSubmit();
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
                .clickSnapshotTab();

        for(int i = 0; i < 5; i++) {
            sleep(2500);

            analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc");

            driver.findElement(By.xpath("//*[@id=\"reports\"]/div[8]/div/div/div[4]/button[1]")).click();

            assertTrue("Modal did not close at level " + levels[i], analyticsPage.isClickable("reportSnapshotSelect"));
        }
    }
}
