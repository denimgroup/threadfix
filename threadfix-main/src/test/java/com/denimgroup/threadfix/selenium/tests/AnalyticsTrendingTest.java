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

@Category(CommunityTests.class)
public class AnalyticsTrendingTest extends BaseDataTest {

    @Test
    public void checkAgingFilter() {
        initializeTeamAndApp();
       /*
        * The following two scans are uploaded
        * because they have dates of October 8
        * and October 9 which makes narrowing the
        * scope of testing easier to narrow.
        */
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
        driver.findElement(By.id("showDateRangeReport")).click();
//      driver.findElement(By.id("startDateInputReport")).sendKeys("05-October-2014");
//      driver.findElement(By.id("endDateInputReport")).sendKeys("09-October-2014");

        WebElement ele = driver.findElement(By.xpath("//*[@class='header']"));
        Actions build = new Actions(driver);
        build.moveByOffset(-250,-100).build().perform();
        build.click().build().perform();

        sleep(15000);
    }

}
