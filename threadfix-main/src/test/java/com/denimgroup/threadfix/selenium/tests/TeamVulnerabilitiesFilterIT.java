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
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Test;
import org.junit.experimental.categories.Category;

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
        initializeTeamAndAppWithIBMScan();

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .setParameterFilter(parameter)
                .toggleSeverityFilter("Critical")
                .toggleSeverityFilter("Medium");

        sleep(1000);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));

        teamDetailPage.clickClearFilters();

        //TODO remove refresh when issue #663 is fixed in 2.2milestone2
        teamDetailPage.refreshPage();

        teamDetailPage.clickVulnerabilitiesTab("45");

        assertTrue("Critical vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Critical"));
        assertTrue("Medium vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Medium"));
        assertTrue("Low vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Low"));
        assertTrue("Info vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Info"));
    }

    /*_________________ Saved Filters _________________*/

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

        teamDetailPage.addSavedFilter(filterName);

        assertTrue("Error message not displayed.", teamDetailPage.isDuplicateNameErrorMessageDisplayed());
    }

    @Test
    public void testSavedFilters() {
        initializeTeamAndAppWithIBMScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";
        String parameter = "username";
        String newFilter = getName();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner)
                .expandFieldControls()
                .setParameterFilter(parameter)
                .toggleSeverityFilter("Medium")
                .toggleSeverityFilter("Critical")
                .expandSavedFilters()
                .addSavedFilter(newFilter);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));

        teamDetailPage.clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71")
                .clickClearFilters()
                .clickLoadFilters()
                .loadSavedFilter(newFilter);

        assertTrue("Only 4 critical vulnerabilities should be shown. There was a problem loading saved filter.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown. There was a problem loading saved filter.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
    }

    /*_________________ Teams and Applications _________________*/

    @Test
    public void testApplicationFilter() {
        initializeTeamAndAppWithIBMScan();
        String appName2 = createApplication(teamName);

        DatabaseUtils.uploadScan(teamName, appName2, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandTeamApplication()
                .addApplicationFilter(appName);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        teamDetailPage.clickClearFilters();

        //TODO remove refresh when issue #663 is fixed in 2.2milestone2
        teamDetailPage.refreshPage();

        teamDetailPage.clickVulnerabilitiesTab("71");

        assertTrue("Only 16 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "16"));
        assertTrue("Only 15 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "15"));
        assertTrue("Only 25 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "25"));
        assertTrue("Only 15 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "15"));

        teamDetailPage.expandTeamApplication().addApplicationFilter(appName2);

        assertTrue("Only 6 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "6"));
        assertTrue("Only 6 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("Only 4 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("Only 10 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "10"));
    }

    /*_________________ Scanner and Merged _________________*/

    @Test
    public void testMergedFindingsFilter() {
        initializeTeamAndAppWithIBMScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandScannerAndMerged()
                .toggleTwoPlus();

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "4"));

        teamDetailPage.toggleFourPlus();

        assertTrue("No Results Found should be displayed.", teamDetailPage.areAllVulnerabilitiesHidden());
    }

    @Test
    public void testScannerFilter() {
        initializeTeamAndAppWithIBMScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandScannerAndMerged()
                .addScannerFilter(scanner);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));
    }

    /*_________________ Field Controls _________________*/

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
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType, defaultVulnerabilityType);

        assertTrue("Only 5 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    @Test
    public void testPathFilter() {
        initializeTeamAndAppWithIBMScan();

        String path = "/demo/EvalInjection2.php";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .setPathFilter(path);

        assertTrue("Only 1 critical vulnerability should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "1"));
        assertTrue("Only 1 info vulnerability should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "1"));
    }

    @Test
    public void testParameterFilter() {
        initializeTeamAndAppWithIBMScan();

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .setParameterFilter(parameter);

        assertTrue("Only 4 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "4"));
        assertTrue("Only 4 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "4"));
        assertTrue("Only 3 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "3"));
    }

    @Test
    public void testSeverityFilter() {
        initializeTeamAndAppWithIBMScan();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .toggleSeverityFilter("Critical")
                .toggleSeverityFilter("Low");

        assertTrue("Critical vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Critical"));
        assertTrue("Low vulnerabilities should be shown.",
                teamDetailPage.isSeverityLevelShown("Low"));

        assertFalse("High vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("High"));
        assertFalse("Medium vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("Medium"));
        assertFalse("Info vulnerabilities should not be shown.",
                teamDetailPage.isSeverityLevelShown("Info"));
    }

    @Test
    public void testStatusFilter() {
        initializeTeamAndAppWithIBMScan();

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .toggleStatusFilter("Open")
                .toggleStatusFilter("Closed");

        assertTrue("No Results Found should be displayed.", teamDetailPage.areAllVulnerabilitiesHidden());
    }

    /*_________________ Aging _________________*/

    @Test
    public void testAgingFilter() {
        initializeTeamAndAppWithIBMScan();
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandAging()
                .toggleLessThan()
                .toggle90Days();

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        teamDetailPage.toggleOneWeek();

        assertTrue("No Results Found should be displayed.", teamDetailPage.areAllVulnerabilitiesHidden());

        teamDetailPage.toggleMoreThan();

        assertTrue("Only 16 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "16"));
        assertTrue("Only 15 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "15"));
        assertTrue("Only 25 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "25"));
        assertTrue("Only 15 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "15"));

        teamDetailPage.toggle90Days();

        assertTrue("Only 6 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "6"));
        assertTrue("Only 6 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "6"));
        assertTrue("Only 4 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "4"));
        assertTrue("Only 10 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "10"));
    }

    /*_________________ Date Range _________________*/
    //TODO this functionality works but there is a bug (358) in FF that stops us from writing a test for now.
}
