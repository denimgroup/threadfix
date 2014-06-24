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
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class TeamDetailFilterIT extends BaseIT{

    @Test
    public void testExpandCollapse() {
        int filtersExpandedControlSize;
        int filtersCollapsedControlSize;
        String teamName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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

    //TODO when name length is limited GitHub issue: 344
    /*@Test
    public void testSavedFilterValidation() {

    }*/

    @Test
    public void testSavedFilters() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";
        String parameter = "username";
        String newFilter = getRandomString(5);

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName1 = getRandomString(8);
        String appName2 = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName1);
        DatabaseUtils.createApplication(teamName, appName2);
        DatabaseUtils.uploadScan(teamName, appName1, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName2, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("71");

        teamDetailPage.expandTeamApplication()
                .addApplicationFilter(appName1);

        assertTrue("Only 10 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "10"));
        assertTrue("Only 9 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "9"));
        assertTrue("Only 21 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "21"));
        assertTrue("Only 5 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "5"));

        teamDetailPage.clickClearFilters();

        assertTrue("Only 16 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "16"));
        assertTrue("Only 15 medium vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Medium", "15"));
        assertTrue("Only 25 low vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Low", "25"));
        assertTrue("Only 15 info vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Info", "15"));

        teamDetailPage.addApplicationFilter(appName2);

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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        String scanner = "IBM Rational AppScan";

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String vulnerabilityType = "Improper Neutralization of Input During Web Page Generation";

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickVulnerabilitiesTab("45");

        teamDetailPage.expandFieldControls()
                .addVulnerabilityTypeFilter(vulnerabilityType);

        assertTrue("Only 5 critical vulnerabilities should be shown.",
                teamDetailPage.isVulnerabilityCountCorrect("Critical", "5"));
    }

    @Test
    public void testPathFilter() {
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String path = "/demo/EvalInjection2.php";

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        String parameter = "username";

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
        String teamName = getRandomString(8);
        String appName = getRandomString(8);

        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan"));
        DatabaseUtils.uploadScan(teamName, appName, ScanContents.SCAN_FILE_MAP.get("Acunetix WVS"));

        TeamDetailPage teamDetailPage = loginPage.login("user", "password")
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
}
