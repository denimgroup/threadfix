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
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsTrendingIT extends BaseDataTest {

    @Test
    public void checkAgingFilter() {
        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickTrendingTab();

        analyticsPage.expandTeamApplicationFilterReport("trendingFilterDiv")
                .addTeamFilterReport(teamName, "trendingFilterDiv")
                .addApplicationFilterReport(appName, "trendingFilterDiv");

        driver.findElement(By.id("showDateControlsReport")).click();
        driver.findElement(By.linkText("Forever")).click();

        Actions build = new Actions(driver);

        build.moveByOffset(-300,-60).build().perform();
        build.click().build().perform();
        assertTrue("Tip does not match", driver.findElement(By.id("areaChartTip")).getText()
                .trim().equals("Time: Oct 8 2014\nTotal: 340\nResurfaced: 0\nNew: 284"));

        build.moveByOffset(-200, 0).build().perform();
        build.click().build().perform();
        assertTrue("Tip does not match", driver.findElement(By.id("areaChartTip")).getText()
                .trim().equals("Time: Oct 6 2014\nTotal: 56\nResurfaced: 0\nNew: 56"));
    }

    @Test
    public void checkFieldFilter() {
        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Old ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickTrendingTab();

        WebElement filterDiv = driver.findElement(By.id("trendingFilterDiv"));
        filterDiv.findElement(By.id("showFieldControlsReport")).click();
        filterDiv.findElement(By.id("showNewReport")).click();
        filterDiv.findElement(By.id("showResurfacedReport")).click();
        filterDiv.findElement(By.id("showInfoReport")).click();
        filterDiv.findElement(By.id("showLowReport")).click();
        filterDiv.findElement(By.id("showMediumReport")).click();
        filterDiv.findElement(By.id("showHighReport")).click();
        filterDiv.findElement(By.id("showCriticalReport")).click();
        filterDiv.findElement(By.id("showFieldControlsReport")).click();
        driver.findElement(By.id("showDateControlsReport")).click();
        driver.findElement(By.linkText("Forever")).click();

        analyticsPage.expandTeamApplicationFilterReport("trendingFilterDiv")
                .addTeamFilterReport(teamName, "trendingFilterDiv")
                .addApplicationFilterReport(appName, "trendingFilterDiv");

        Actions build = new Actions(driver);

        build.moveByOffset(-300,-60).build().perform();
        build.click().build().perform();
        assertTrue("Tip does not match", driver.findElement(By.id("areaChartTip")).getText()
                .trim().equals("Time: Oct 8 2014\nTotal: 340\nCritical: 0\nHigh: 35\nMedium: 93\nLow: 109\nInfo: 103"));
        driver.findElement(By.id("showDateControlsReport")).click();
        driver.findElement(By.id("showDateControlsReport")).click();

        build.moveByOffset(-500,-60).perform();
        build.click().build().perform();
        assertTrue("Tip does not match", driver.findElement(By.id("areaChartTip")).getText()
                .trim().equals("Time: Oct 6 2014\nTotal: 56\nCritical: 0\nHigh: 1\nMedium: 16\nLow: 22\nInfo: 17"));
    }

    @Test
    public void expandCollapseTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickTrendingTab();

        int filtersCollapsedSize = analyticsPage.getFilterDivHeight("trendingFilterDiv");
        analyticsPage.toggleAllFilterReport("trendingFilterDiv");

        int filtersExpandedSize = analyticsPage.getFilterDivHeight("trendingFilterDiv");
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilterReport("trendingFilterDiv");
        assertFalse("Filters were not collapsed.",
                filtersExpandedSize == analyticsPage.getFilterDivHeight("trendingFilterDiv"));
    }
}
