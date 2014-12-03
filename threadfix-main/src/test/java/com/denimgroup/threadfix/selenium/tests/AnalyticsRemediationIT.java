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
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsRemediationIT extends BaseDataTest {

    private AnalyticsPage analyticsPage;
    private ApplicationDetailPage applicationDetailPage;

    public String initialize() {
        initializeTeamAndAppWithIBMScan();
        String tagName = createTag();
        DatabaseUtils.attachAppToTag(tagName,appName,teamName);

        analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .sleepOnArrival(15000)
                .clickRemediationTab(true)
                .sleepOnArrival(3000)
                .expandTagFilter("complianceFilterDiv")
                .addTagFilter(tagName,"complianceFilterDiv")
                .expandAgingFilterReport("complianceFilterDiv")
                .toggleAgingFilterReport("Forever","complianceFilterDiv")
                .sleepOnArrival(2000);

        return tagName;
    }

    @Test
    public void checkStartingEndingCount() {
        String tagName = initialize();

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("OWASP Zed Attack Proxy"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("AppScanEnterprise"));

        analyticsPage.clickAnalyticsLink()
                .clickRemediationTab(false)
                .expandTagFilter("complianceFilterDiv")
                .addTagFilter(tagName,"complianceFilterDiv")
                .expandAgingFilterReport("complianceFilterDiv")
                .toggleAgingFilterReport("Forever", "complianceFilterDiv");

        assertTrue("Starting count is incorrect",
                driver.findElement(By.cssSelector("#\\31")).getText().equals("0"));

        assertTrue("Ending count is incorrect",
                driver.findElement(By.cssSelector("#\\32")).getText().equals("21"));
    }

    @Test
    public void checkAppNameNavigation() {
        initialize();

        analyticsPage.clickAppName(appName);

        assertTrue("Link did not navigate correctly", driver.findElement(By.id("nameText")).getText().equals(appName));
    }

    @Test
    public void checkTeamNameNavigation() {
        initialize();

        analyticsPage.clickTeamName(teamName);

        assertTrue("Link did not navigate correctly", driver.findElement(By.id("name")).getText().contains(teamName));
    }

    @Test
    public void testOpenVulns() {
        initialize();

        assertTrue("Open Vulnerabilities are correct", driver.findElement(By.id("vulnName0"))
                .getText().equals("Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')") );
    }

    @Test
    public void testClosedVulns() {
        String tagName = initialize();

        analyticsPage.clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName,teamName)
                .expandVulnerabilityByType("Critical79")
                .checkVulnerabilityByType("Critical790")
                .clickVulnerabilitiesActionButton()
                .clickCloseVulnerabilitiesButton()
                .clickAnalyticsLink()
                .sleepOnArrival(15000)
                .clickRemediationTab(false)
                .expandTagFilter("complianceFilterDiv")
                .addTagFilter(tagName,"complianceFilterDiv")
                .expandAgingFilterReport("complianceFilterDiv")
                .toggleAgingFilterReport("Forever", "complianceFilterDiv");;

        assertTrue("Closed vulnerability is not displayed.",
                driver.findElements(By.id("vulnName0")).toArray().length == 2 ||
                        driver.findElements(By.id("vulnName0")).toArray().length == 4);
    }

    @Test
    public void attachComment() {
        String tagName = initialize();
        String testComment = getName();

        analyticsPage.clickViewMore("0").clickAddComment()
                .setCommentText(testComment)
                .clickSubmitComment()
                .clickAnalyticsLink()
                .clickRemediationTab(true)
                .expandTagFilter("complianceFilterDiv")
                .addTagFilter(tagName,"complianceFilterDiv")
                .expandAgingFilterReport("complianceFilterDiv")
                .toggleAgingFilterReport("Forever", "complianceFilterDiv")
                .expandVulnComments("0");

        assertTrue("Comment not attached properly", analyticsPage.getCommentText("0").equals(testComment));
    }

    @Test
    public void testNumVulns() {
        initialize();

        assertTrue("There aren't enough vulnerabilities shown on the page.",
                !driver.findElements(By.id("vulnName44")).isEmpty());
        assertTrue("There are too many vulnerabilities shown.", driver.findElements(By.id("vulnName50")).isEmpty());
    }
}