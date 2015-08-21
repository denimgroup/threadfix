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
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class TeamVulnerabilitiesFilterIT extends BaseDataTest{

    @Test
    public void testExpandCollapse() {
        int filtersExpandedControlSize;
        int filtersCollapsedControlSize;
        String teamName = createTeam();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab();

        filtersCollapsedControlSize = teamDetailPage.getFilterDivHeight();
        teamDetailPage.toggleAllFilters();

        filtersExpandedControlSize = teamDetailPage.getFilterDivHeight();
        assertFalse("Filters were not expanded.", filtersCollapsedControlSize == filtersExpandedControlSize);

        teamDetailPage.toggleAllFilters();
        assertTrue("Filters were not collapsed.",
                filtersCollapsedControlSize == teamDetailPage.getFilterDivHeight());
    }

    @Test
    public void testClearFilter() {
        initializeTeamAndAppWithIbmScan();

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .setParameterFilter(parameter)
                .toggleSeverityFilter("Low")
                .toggleSeverityFilter("Info");

        sleep(1000);

        assertTrue("Only 4 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));

        teamDetailPage.clickClearFilters();

        teamDetailPage.clickVulnerabilitiesTab("44");

        assertTrue("High vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("High"));
        assertTrue("Medium vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Medium"));
        assertTrue("Low vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Low"));
        assertTrue("Info vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Info"));
    }

    //===========================================================================================================
    // Saved Filters
    //===========================================================================================================

    @Test
    public void testSavedFilterFieldValidation() {
        initializeTeamAndApp();
        String tooLong = getRandomString(26);
        String goodLength = getRandomString(25);

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("0")
                .expandSavedFilters()
                .addInvalidNameSavedFilter(tooLong);

        assertTrue("The name should be too long to save.", teamDetailPage.isSaveFilterDisabled());

        teamDetailPage.addSavedFilter(goodLength);

        assertTrue("Success message not present.", teamDetailPage.isSavedFilterSuccessMessageDisplayed());

        teamDetailPage.clickLoadFilters();

        assertTrue("Saved filter should be in list of saved filters.", teamDetailPage.isSavedFilterPresent(goodLength));
    }

    @Test
    public void testDuplicateNameSavedFilter() {
        initializeTeamAndApp();
        String filterName = getName();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("0")
                .expandSavedFilters()
                .addSavedFilter(filterName);

        assertTrue("Success message not present.", teamDetailPage.isSavedFilterSuccessMessageDisplayed());

        TeamDetailPage teamDetailPage1 = teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("0")
                .expandSavedFilters()
                .addInvalidNameSavedFilter(filterName);

        driver.findElement(By.id("saveFilterButton")).click();

        assertTrue("Error message not displayed.", teamDetailPage1.isDuplicateNameErrorMessageDisplayed());
    }

    @Test
    public void testSavedFilters() {
        initializeTeamAndAppWithIbmScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Security AppScan Standard";
        String parameter = "username";
        String newFilter = getName();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("69");

        teamDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner)
                .expandFieldControls()
                .setParameterFilter(parameter)
                .toggleSeverityFilter("Low")
                .toggleSeverityFilter("Info")
                .expandSavedFilters()
                .addSavedFilter(newFilter);

        teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("69")
                .clickClearFilters()
                .clickLoadFilters()
                .loadSavedFilter(newFilter);

        sleep(5000);

        assertTrue("Only 4 high vulnerabilities should be shown. There was a problem loading saved filter.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown. There was a problem loading saved filter.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
    }

    //===========================================================================================================
    // Teams and Applications
    //===========================================================================================================

    @Test
    public void testApplicationFilter() {
        initializeTeamAndAppWithIbmScan();
        String appName2 = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName2, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("69");

        teamDetailPage.expandTeamApplication()
                .addApplicationFilter(appName);

        assertTrue("Only 10 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        teamDetailPage.clickClearFilters();

        teamDetailPage.clickVulnerabilitiesTab("69");

        assertTrue("Only 16 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "16"));
        assertTrue("Only 14 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "14"));
        assertTrue("Only 25 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "25"));
        assertTrue("Only 14 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "14"));

        teamDetailPage.addApplicationFilter(appName2);

        assertTrue("Only 6 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "6"));
        assertTrue("Only 6 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("Only 4 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("Only 9 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "9"));
    }

    //===========================================================================================================
    // Scanner and Merged
    //===========================================================================================================

    @Test
    public void testMergedFindingsFilter() {
        initializeTeamAndAppWithIbmScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("69");

        teamDetailPage.expandScannerAndMerged()
                .toggleTwoPlus();

        assertTrue("Only 4 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "4"));

        teamDetailPage.toggleFourPlus();

        assertTrue("No Results Found should be displayed.", teamDetailPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testScannerFilter() {
        initializeTeamAndAppWithIbmScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Security AppScan Standard";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("69");

        teamDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner);

        assertTrue("Only 10 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "10"));
        assertTrue("Only 8 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "8"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));
    }

    //===========================================================================================================
    // Field Controls
    //===========================================================================================================

    @Test
    public void testVulnerabilityTypeFilter() {
        String teamName = createTeam();
        String appName = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation";
        String defaultVulnerabilityType = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') (CWE 79)";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType, defaultVulnerabilityType);

        assertTrue("Only 5 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "5"));
    }

    @Test
    public void testPathFilter() {
        initializeTeamAndAppWithIbmScan();

        String path = "/demo/EvalInjection2.php";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .setPathFilter(path);

        assertTrue("Only 1 high vulnerability should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "1"));
        assertTrue("Only 1 info vulnerability should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "1"));
    }

    @Test
    public void testParameterFilter() {
        initializeTeamAndAppWithIbmScan();

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .setParameterFilter(parameter);

        assertTrue("Only 4 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
        assertTrue("Only 3 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "3"));
    }

    @Test
    public void testSeverityFilter() {
        initializeTeamAndAppWithIbmScan();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .toggleSeverityFilter("Medium")
                .toggleSeverityFilter("Info");

        assertTrue("High vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("High"));
        assertTrue("Low vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Low"));

        assertFalse("Critical vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("Critical"));
        assertFalse("Medium vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("Medium"));
        assertFalse("Info vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("Info"));
    }

    @Test
    public void testStatusFilter() {
        initializeTeamAndAppWithIbmScan();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("44");

        teamDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("No Results Found should be displayed.", teamDetailPage.areAllVulnerabilitiesHidden());
    }

    //===========================================================================================================
    // Aging
    //===========================================================================================================

    @Test
    public void testAgingFilter() {
        initializeTeamAndApp();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("25");

        teamDetailPage.expandAging()
                .toggleLessThan()
                .toggle90Days();

        assertTrue("There should be no vulnerabilities displayed.",
                teamDetailPage.areAllVulnerabilitiesHidden());

        teamDetailPage.toggleOneWeek();

        assertTrue("There should be no vulnerabilities displayed.",
                teamDetailPage.areAllVulnerabilitiesHidden());

        teamDetailPage.toggleMoreThan();

        assertTrue("6 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "6"));
        assertTrue("6 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("4 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("9 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "9"));

        teamDetailPage.toggle90Days();

        assertTrue("6 high vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("High", "6"));
        assertTrue("6 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("4 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("9 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "9"));
    }

    //===========================================================================================================
    // Date Range
    //===========================================================================================================
    //TODO Add test once DGTF-1833 is resolved
}
