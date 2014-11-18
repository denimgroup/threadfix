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
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.interactions.Actions;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsVulnerabilitiesFilterIT extends BaseDataTest{

    @Test
    public void expandCollapseTest() {
        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        int filtersCollapsedSize = analyticsPage.getFilterDivHeight("vulnSearchFilterDiv");
        analyticsPage.toggleAllFilter("vulnSearchFilterDiv", true);

        int filtersExpandedSize = analyticsPage.getFilterDivHeight("vulnSearchFilterDiv");
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilter("vulnSearchFilterDiv", false);
        assertFalse("Filters were not collapsed.",
                filtersExpandedSize == analyticsPage.getFilterDivHeight("vulnSearchFilterDiv"));
    }

    @Test
    public void teamFilterTest() {
        initializeTeamAndAppWithIBMScan();
        String teamName2 = createTeam();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter("vulnSearchFilterDiv")
                .addTeamFilter(teamName, "vulnSearchFilterDiv");

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter("vulnSearchFilterDiv")
                .addTeamFilter(teamName2, "vulnSearchFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void applicationFilterTest() {
        initializeTeamAndAppWithIBMScan();
        String teamName2 = createTeam();
        String appName2 = createApplication(teamName2);

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter("vulnSearchFilterDiv")
                .addApplicationFilter(appName,"vulnSearchFilterDiv");

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter("vulnSearchFilterDiv")
                .addApplicationFilter(appName2,"vulnSearchFilterDiv");

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void checkDeletedVulnerability() {
        initializeTeamAndAppWithIBMScan();

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickScansTab();

        ScanDetailPage scanDetailPage = applicationDetailPage.clickViewScan();

        FindingDetailPage findingDetailPage = scanDetailPage.clickViewFinding();

        VulnerabilityDetailPage vulnerabilityDetailPage = findingDetailPage.clickViewVulnerability()
                .clickToggleMoreInfoButton();

        AnalyticsPage analyticsPage = vulnerabilityDetailPage.clickCloseVulnerabilityButton()
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter("vulnSearchFilterDiv")
                .addApplicationFilter(appName, "vulnSearchFilterDiv");

        assertTrue("Only 9 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "9"));
    }

    @Test
    public void checkAnalyticsPage() {
        initializeTeamAndAppWithIBMScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickViewAppLink(appName, teamName)
                .clickViewMoreVulnerabilityTrending();

        assertTrue("Incorrect Navigation", analyticsPage.isReportCorrect());

        analyticsPage.clickVulnerabilitySearchTab();

        assertTrue("Vulnerabilities Lists are not Present", analyticsPage.isElementPresent("vulnSearchFilterDiv"));
    }

    @Test
    public void checkAgingFilter() {
        initializeTeamAndAppWithIBMScan();

        AnalyticsPage analyticsPage = loginPage.defaultLogin()
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter("vulnSearchFilterDiv")
                .addTeamFilter(teamName, "vulnSearchFilterDiv");

        driver.findElement(By.id("showDateControls")).click();
        driver.findElement(By.linkText("More Than")).click();
        driver.findElement(By.linkText("1 Week")).click();

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        driver.findElement(By.linkText("Less Than")).click();

        assertTrue("There should have been no results found", driver.findElement(By.id("noResultsFound"))
                .getText().trim().equals("No results found."));
    }
}
