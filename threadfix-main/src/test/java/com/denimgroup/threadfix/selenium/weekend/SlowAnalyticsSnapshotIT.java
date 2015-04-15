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
package com.denimgroup.threadfix.selenium.weekend;

import com.denimgroup.threadfix.WeekendTests;
import com.denimgroup.threadfix.selenium.pages.AnalyticsPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertTrue;

@Category(WeekendTests.class)
public class SlowAnalyticsSnapshotIT extends BaseDataTest {

    @Test
    public void pieD3WedgeNavigation() {
        initializeTeamAndAppWithWebInspectScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("New ZAP Scan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));
        String[] levels = {"Info","Low","Medium","High","Critical"};

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink();

        for(int i = 0; i < 5; i++) {
            analyticsPage.clickSnapshotTab(true);

            analyticsPage.waitForElement(driver.findElement(By.id("pointInTime" + levels[i] + "Arc")));

            analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc")
                    .clickModalSubmit();

            assertTrue("Navigation @ level " + levels[i] + " failed", analyticsPage.checkCorrectFilterLevel(levels[i]));
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
            analyticsPage.clickSnapshotTab(true)
                    .expandTeamApplicationFilterReport("snapshotFilterDiv")
                    .addTeamFilterReport(teamName, "snapshotFilterDiv");

            sleep(2500);

            analyticsPage.clickSVGElement("pointInTime" + levels[i] + "Arc");

            String numModal = driver.findElement(By.id("header0")).getText().split("\\s+")[1].trim();
            String numBadge = driver.findElement(By.id("totalBadge" + levels[i])).getText().trim();

            assertTrue("Modal total at level " + levels[i] + " does not match badge",
                    numBadge.equals(numModal));

            analyticsPage.clickModalSubmit();
        }
    }
}
