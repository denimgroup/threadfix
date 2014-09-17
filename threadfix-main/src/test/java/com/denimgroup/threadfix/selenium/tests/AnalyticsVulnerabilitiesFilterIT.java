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
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class AnalyticsVulnerabilitiesFilterIT extends BaseIT{

    @Test
    public void expandCollapseTest() {
        int filtersExpandedSize;
        int filtersCollapsedSize;

        AnalyticsPage analyticsPage = loginPage.login("user", "password")
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        filtersCollapsedSize = analyticsPage.getFilterDivHeight();
        analyticsPage.toggleAllFilter();

        filtersExpandedSize = analyticsPage.getFilterDivHeight();
        assertFalse("Filters were not expanded.", filtersCollapsedSize == filtersExpandedSize);

        analyticsPage = analyticsPage.toggleAllFilter();
        assertFalse("Filters were not collapsed.",
                filtersExpandedSize == analyticsPage.getFilterDivHeight());
    }

    @Test
    public void teamFilterTest() {
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);
        String appName1 = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);
        DatabaseUtils.createApplication(teamName1, appName1);
        DatabaseUtils.uploadScan(teamName1, appName1, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        AnalyticsPage analyticsPage = loginPage.login("user", "password")
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter()
                .addTeamFilter(teamName1);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter()
                .addTeamFilter(teamName2);

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void applicationFilterTest() {
        String teamName1 = getRandomString(8);
        String teamName2 = getRandomString(8);
        String appName1 = getRandomString(8);
        String appName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName1);
        DatabaseUtils.createTeam(teamName2);
        DatabaseUtils.createApplication(teamName1, appName1);
        DatabaseUtils.createApplication(teamName2, appName2);
        DatabaseUtils.uploadScan(teamName1, appName1, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        AnalyticsPage analyticsPage = loginPage.login("user", "password")
                .clickAnalyticsLink()
                .clickVulnerabilitySearchTab();

        analyticsPage.expandTeamApplicationFilter()
                .addApplicationFilter(appName1);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Info", "5"));

        analyticsPage.clearFilter()
                .addApplicationFilter(appName2);

        assertTrue("There should be no results shown.",
                analyticsPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void checkDeletedVulnerability() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName , ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        ApplicationDetailPage applicationDetailPage = loginPage.login("user", "password")
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

        analyticsPage.expandTeamApplicationFilter()
                .addApplicationFilter(appName);
        assertTrue("Only 10 critical vulnerabilities should be shown.",
                analyticsPage.isVulnerabilityCountCorrect("Critical", "9"));
    }
}
