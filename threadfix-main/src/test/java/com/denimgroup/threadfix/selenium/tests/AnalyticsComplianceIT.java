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
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsComplianceIT extends BaseDataTest {

    @Test
    public void checkStartingEndingCount() {
        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("OWASP Zed Attack Proxy"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickTagsLink()
                .createNewTag(appName)
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName,teamName);

        applicationDetailPage.clickEditDeleteBtn()
                .attachTag(appName)
                .clickModalSubmit();

        applicationDetailPage.clickAnalyticsLink()
                .clickComplianceTab(false)
                .expandTagFilter("complianceFilterDiv")
                .addTagFilter(appName,"complianceFilterDiv")
                .expandAgingFilterReport("complianceFilterDiv")
                .toggleAgingFilterReport("Forever","complianceFilterDiv");

        assertTrue("Starting count is incorrect",
                driver.findElement(By.cssSelector("#\\31")).getText().equals("0"));

        assertTrue("Ending count is incorrect",
                driver.findElement(By.cssSelector("#\\32")).getText().equals("16"));
    }

}